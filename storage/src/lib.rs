mod stream;

use std::borrow::Cow;
use std::marker::Unpin;

use async_stream::try_stream;
use bytes::{Buf, Bytes};
use futures::{future::ok, stream::once, Stream, StreamExt};
use http::{header::CONTENT_ENCODING, HeaderValue, StatusCode};
use s3::{creds::error::CredentialsError, error::S3Error, Bucket};
pub use s3::{creds::Credentials, Region};
use serde::Deserialize;

pub struct Storage {
    bucket: Bucket,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct StorageConfig {
    /// Bucket name to use for storing data and index
    #[arg(env, long = "storage-bucket")]
    pub bucket: Option<String>,

    /// Storage region to use
    #[arg(env, long = "storage-region")]
    pub region: Option<Region>,

    /// Storage endpoint to use
    #[arg(env, long = "storage-endpoint")]
    pub endpoint: Option<String>,

    /// Access key for using storage
    #[arg(env, long = "storage-access-key")]
    pub access_key: Option<String>,

    /// Secret key for using storage
    #[arg(env, long = "storage-secret-key")]
    pub secret_key: Option<String>,
}

impl StorageConfig {
    pub fn create(&mut self, default_bucket: &str, devmode: bool) -> Result<Storage, Error> {
        if devmode {
            self.access_key = Some("admin".to_string());
            self.secret_key = Some("password".to_string());
            self.bucket = Some(default_bucket.to_string());
            Ok(Storage::new(self)?)
        } else {
            Ok(Storage::new(self)?)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("internal storage error")]
    Internal,
    #[error("object not found")]
    NotFound,
    #[error("error with credentials")]
    Credentials(CredentialsError),
    #[error("error with s3 backend {0}")]
    S3(S3Error),
    #[error("I/O error {0}")]
    Io(std::io::Error),
    #[error("invalid storage key {0}")]
    InvalidKey(String),
    #[error("unexpected encoding {0}")]
    Encoding(String),
}

impl From<CredentialsError> for Error {
    fn from(e: CredentialsError) -> Self {
        Self::Credentials(e)
    }
}

impl From<S3Error> for Error {
    fn from(e: S3Error) -> Self {
        if let S3Error::HttpFailWithBody(status, _) = e {
            if status == 404 {
                return Self::NotFound;
            }
        }
        Self::S3(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        match e {
            Error::Io(e) => e,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}

impl From<http::header::InvalidHeaderName> for Error {
    fn from(_: http::header::InvalidHeaderName) -> Self {
        Self::Internal
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(_: http::header::InvalidHeaderValue) -> Self {
        Self::Internal
    }
}

const DATA_PATH: &str = "/data/";
const INDEX_PATH: &str = "/index";
const VERSION_HEADER: &str = "x-amz-meta-version";
const VERSION: u32 = 1;

pub struct Head {
    pub status: StatusCode,
    pub content_encoding: Option<String>,
}

impl Storage {
    pub fn new(config: &StorageConfig) -> Result<Self, Error> {
        let credentials = if let (Some(access_key), Some(secret_key)) = (&config.access_key, &config.secret_key) {
            Credentials {
                access_key: Some(access_key.into()),
                secret_key: Some(secret_key.into()),
                security_token: None,
                session_token: None,
                expiration: None,
            }
        } else {
            Credentials::default()?
        };

        let region = config.region.clone().unwrap_or_else(|| Region::Custom {
            region: "eu-central-1".to_owned(),
            endpoint: config.endpoint.clone().unwrap_or("http://localhost:9000".to_string()),
        });

        let bucket = config.bucket.as_deref().expect("Required parameter bucket was not set");
        let bucket = Bucket::new(bucket, region, credentials)?.with_path_style();
        Ok(Self { bucket })
    }

    pub fn is_index(&self, key: &str) -> bool {
        format!("/{}", key) == INDEX_PATH
    }

    pub fn key_from_event(record: &Record) -> Result<(Cow<str>, String), Error> {
        if let Ok(decoded) = urlencoding::decode(record.key()) {
            let key = decoded
                .strip_prefix("data/")
                .map(|s| s.to_string())
                .unwrap_or(decoded.to_string());
            Ok((decoded, key))
        } else {
            Err(Error::InvalidKey(record.key().to_string()))
        }
    }

    pub async fn put_stream<'a, S, B, E>(
        &self,
        key: &'a str,
        content_type: &'a str,
        encoding: Option<&str>,
        data: &mut S,
    ) -> Result<u16, Error>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: Buf + 'a,
        E: Into<std::io::Error>,
    {
        let mut headers = http::HeaderMap::new();
        headers.insert(VERSION_HEADER, VERSION.into());
        headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_str(encoding.unwrap_or("zstd")).unwrap(),
        );
        let bucket = self.bucket.with_extra_headers(headers);
        let path = format!("{}{}", DATA_PATH, key);
        let mut rdr = stream::encode(encoding, data)?;
        Ok(bucket
            .put_object_stream_with_content_type(&mut rdr, path, content_type)
            .await?)
    }

    pub async fn put_json_slice<'a>(&self, key: &'a str, json: &'a [u8]) -> Result<u16, Error> {
        let mut stream = once(ok::<_, std::io::Error>(json));
        self.put_stream(key, "application/json", None, &mut stream).await
    }

    // This will load the entire S3 object into memory
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        self.get_object(&path).await
    }

    pub async fn get_head(&self, key: &str) -> Result<Head, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        let (head, status) = self.bucket.head_object(&path).await?;
        Ok(Head {
            status: StatusCode::from_u16(status).map_err(|_| Error::Internal)?,
            content_encoding: head.content_encoding,
        })
    }

    // Returns unencoded stream
    pub async fn get_decoded_stream(&self, key: &str) -> Result<impl Stream<Item = Result<Bytes, Error>>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        self.get_object_stream(&path).await
    }

    // Returns encoded stream
    pub async fn get_encoded_stream(&self, key: &str) -> Result<impl Stream<Item = Result<Bytes, Error>>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        let mut s = self.bucket.get_object_stream(&path).await?;
        Ok(try_stream! { while let Some(chunk) = s.bytes().next().await { yield chunk?; }})
    }

    // Get the data associated with an event record.
    // This will load the entire S3 object into memory
    pub async fn get_for_event(&self, record: &Record) -> Result<(String, Vec<u8>), Error> {
        // Record keys are URL encoded
        if let Ok((decoded, key)) = Self::key_from_event(record) {
            let ret = self.get_object(&decoded).await?;
            Ok((key, ret))
        } else {
            Err(Error::InvalidKey(record.key().to_string()))
        }
    }

    pub async fn put_index(&self, index: &[u8]) -> Result<(), Error> {
        self.bucket.put_object(INDEX_PATH, index).await?;
        Ok(())
    }

    pub async fn get_index(&self) -> Result<Vec<u8>, Error> {
        let data = self.bucket.get_object(INDEX_PATH).await?;
        Ok(data.to_vec())
    }

    pub fn decode_event(&self, event: &[u8]) -> Result<StorageEvent, Error> {
        serde_json::from_slice::<StorageEvent>(event).map_err(|_e| Error::Internal)
    }

    // Expects the actual S3 path
    // This will load the entire S3 object into memory
    async fn get_object(&self, path: &str) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![];
        let mut stream = self.get_object_stream(path).await?;
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?)
        }
        Ok(bytes)
    }

    // Expects the actual S3 path and returns a JSON stream
    async fn get_object_stream(&self, path: &str) -> Result<impl Stream<Item = Result<Bytes, Error>>, Error> {
        let (head, _status) = self.bucket.head_object(path).await?;
        let mut s = self.bucket.get_object_stream(path).await?;
        let stream = try_stream! {
            while let Some(chunk) = s.bytes().next().await {
                yield chunk?;
            }
        };
        stream::decode(head.content_encoding, stream.boxed())
    }

    pub async fn delete(&self, key: &str) -> Result<u16, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        Ok(self.bucket.delete_object(path).await.map(|r| r.status_code())?)
    }
}

const PUT_EVENT: &str = "ObjectCreated:Put";
const MULTIPART_PUT_EVENT: &str = "ObjectCreated:CompleteMultipartUpload";
const DELETE_EVENT: &str = "ObjectRemoved:Delete";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EventType {
    Put,
    Delete,
    Other,
}

#[derive(Deserialize, Debug)]
pub struct StorageEvent {
    #[serde(rename = "Records")]
    pub records: Vec<Record>,
}

#[derive(Deserialize, Debug)]
pub struct Record {
    #[serde(rename = "s3")]
    s3: S3Data,
    #[serde(rename = "eventName")]
    event_name: String,
}

impl Record {
    pub fn event_type(&self) -> EventType {
        if self.event_name.ends_with(PUT_EVENT) || self.event_name.ends_with(MULTIPART_PUT_EVENT) {
            EventType::Put
        } else if self.event_name.ends_with(DELETE_EVENT) {
            EventType::Delete
        } else {
            EventType::Other
        }
    }

    pub fn key(&self) -> &str {
        &self.s3.object.key
    }

    pub fn bucket(&self) -> &str {
        &self.s3.bucket.name
    }
}

#[derive(Deserialize, Debug)]
pub struct S3Data {
    #[serde(rename = "object")]
    object: S3Object,
    #[serde(rename = "bucket")]
    bucket: S3Bucket,
}

#[derive(Deserialize, Debug)]
pub struct S3Object {
    #[serde(rename = "key")]
    key: String,
}

#[derive(Deserialize, Debug)]
pub struct S3Bucket {
    #[serde(rename = "name")]
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_decode() {
        let event = r#"{
        "Records": [
            {
            "awsRegion": "eu-west-1",
            "eventName": "ObjectCreated:Put",
            "eventSource": "aws:s3",
            "eventTime": "2023-05-11T13:25:03.104Z",
            "eventVersion": "2.1",
            "requestParameters": {
                "sourceIPAddress": "10.0.220.140"
            },
            "responseElements": {
                "x-amz-id-2": "PmiHPIpmhpjmmijsu6xXEtk9E2NEK29FBDtZcvGU1jgt7EFFopTzWFPyv/nZwR60Qx5nCvPvVbXKV0wkg87aiSvbgRaIgK8x",
                "x-amz-request-id": "X3ZPARGNVP97GNFA"
            },
            "s3": {
                "bucket": {
                    "arn": "arn:aws:s3:::bombastic",
                    "name": "bombastic",
                    "ownerIdentity": {
                        "principalId": "A269W3T43498LN"
                    }
                },
                "configurationId": "stored",
                "object": {
                    "eTag": "7e1f5bce30a48e7618d8d5619d51a20b",
                    "key": "data/mysbom11",
                    "sequencer": "00645CECAF0EE0E7F8",
                    "size": 49312
                },
                "s3SchemaVersion": "1.0"
            },
            "userIdentity": {
                "principalId": "AWS:AIDAUA4TFOLTSNJ5R5SJW"
            }
            }
        ]
        }"#;

        let decoded = serde_json::from_str::<StorageEvent>(event).unwrap();

        assert_eq!(1, decoded.records.len());
        let decoded = &decoded.records[0];
        assert_eq!(decoded.event_type(), EventType::Put);
        assert_eq!(decoded.key(), "data/mysbom11");
        assert_eq!(decoded.bucket(), "bombastic");
    }

    #[test]
    fn test_minio_decode() {
        let event = r#"{"EventName":"s3:ObjectCreated:Put","Key":"vexination/index","Records":[{"eventVersion":"2.0","eventSource":"minio:s3","awsRegion":"","eventTime":"2023-06-05T11:04:06.851Z","eventName":"s3:ObjectCreated:Put","userIdentity":{"principalId":"admin"},"requestParameters":{"principalId":"admin","region":"","sourceIPAddress":"10.89.1.9"},"responseElements":{"content-length":"0","x-amz-id-2":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","x-amz-request-id":"1765BE755F95378E","x-minio-deployment-id":"7637fbd9-a700-4918-bc9d-f7929adf0d8f","x-minio-origin-endpoint":"http://10.89.1.9:9000"},"s3":{"s3SchemaVersion":"1.0","configurationId":"Config","bucket":{"name":"vexination","ownerIdentity":{"principalId":"admin"},"arn":"arn:aws:s3:::vexination"},"object":{"key":"index","size":2851,"eTag":"8aebf225551d1a9c71914a91bf36c7e3","contentType":"application/octet-stream","userMetadata":{"content-type":"application/octet-stream"},"sequencer":"1765BE756000DEDE"}},"source":{"host":"10.89.1.9","port":"","userAgent":""}}]}"#;
        let decoded = serde_json::from_str::<StorageEvent>(event).unwrap();

        assert_eq!(1, decoded.records.len());
        let decoded = &decoded.records[0];
        assert_eq!(decoded.event_type(), EventType::Put);
        assert_eq!(decoded.key(), "index");
        assert_eq!(decoded.bucket(), "vexination");
    }
}
