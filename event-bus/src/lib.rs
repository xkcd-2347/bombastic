use std::fmt::Debug;

pub trait Event {
    type Error: Debug;
    fn payload(&self) -> Option<&[u8]>;
    fn commit(&self) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
pub trait EventBus {
    type Error: Debug;
    type Event<'m>: Event
    where
        Self: 'm;
    async fn poll<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error>;

    async fn send(&self, data: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "kafka")]
pub mod kafka;
