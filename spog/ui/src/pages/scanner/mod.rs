mod inspect;
// mod unknown;
pub mod upload;

use analytics_next::TrackingEvent;
use anyhow::bail;
use bombastic_model::prelude::SBOM;
use inspect::Inspect;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use serde_json::{json, Value};
use spog_ui_utils::{
    analytics::*,
    config::*,
    hints::{Hint as HintView, Hints},
    tracking_event,
};
use std::{rc::Rc, str::FromStr};
use upload::Upload;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

tracking_event!(ClickLearn: "Click SBOM scanner learn" => None);
tracking_event!(Reset: "Reset SBOM scanner" => None);

pub struct ParseOutcome<'a>(&'a Result<SBOM, anyhow::Error>);

impl<'a> From<ParseOutcome<'a>> for TrackingEvent<'static> {
    fn from(value: ParseOutcome<'a>) -> Self {
        (
            "ScanSBOMPage Preflight Check",
            match &value.0 {
                Ok(value) => json!({
                    "ok": {
                        "type": value.type_str(),
                    }
                }),
                Err(err) => json!({"err": err.to_string()}),
            },
        )
            .into()
    }
}

fn is_supported_package(purl: &str) -> bool {
    match PackageUrl::from_str(purl) {
        Ok(package) => {
            package.ty() == "maven"
                || package.ty() == "gradle"
                || package.ty() == "npm"
                || package.ty() == "golang"
                || package.ty() == "pypi"
        }
        Err(_) => false,
    }
}

pub fn parse_and_validate(data: &[u8]) -> Result<SBOM, anyhow::Error> {
    parse(data).and_then(|_| validate(data))
}

pub fn parse(data: &[u8]) -> Result<SBOM, anyhow::Error> {
    let sbom = SBOM::parse(data)?;

    #[allow(clippy::single_match)]
    match &sbom {
        SBOM::CycloneDX(_bom) => {
            // re-parse to check for the spec version
            let json = serde_json::from_slice::<Value>(data).ok();
            let spec_version = json.as_ref().and_then(|json| json["specVersion"].as_str());

            match spec_version {
                Some("1.3") | Some("1.4") | Some("1.5") => {}
                Some(other) => bail!("Unsupported CycloneDX version: {other}"),
                None => bail!("Unable to detect CycloneDX version"),
            }
        }
        SBOM::SPDX(_bom) => {
            let _json = serde_json::from_slice::<Value>(data).ok();
        }
    }

    Ok(sbom)
}

pub fn validate(data: &[u8]) -> Result<SBOM, anyhow::Error> {
    let sbom = SBOM::parse(data)?;

    #[allow(clippy::single_match)]
    match &sbom {
        SBOM::CycloneDX(_bom) => {
            // re-parse to check for the spec version
            let json = serde_json::from_slice::<Value>(data).ok();

            let supported_packages = json.as_ref().map(|json| {
                if let Some(components) = json["components"].as_array() {
                    let are_all_supported_packages = components
                        .iter()
                        .filter_map(|external_ref| external_ref["purl"].as_str())
                        .all(is_supported_package);
                    are_all_supported_packages
                } else {
                    false
                }
            });

            match supported_packages {
                Some(false) => {
                    // bail!("The SBOM contains package type(s) not supported by Dependency Analytics. The Dependency Analytics report may be unavailable for this SBOM.")
                }
                _ => {}
            }
        }
        SBOM::SPDX(_bom) => {
            let json = serde_json::from_slice::<Value>(data).ok();

            let supported_packages = json.as_ref().map(|json| {
                if let Some(packages) = json["packages"].as_array() {
                    let are_all_supported_packages = packages
                        .iter()
                        .filter_map(|package| package["externalRefs"].as_array())
                        .flatten()
                        .filter_map(|external_ref| external_ref["referenceLocator"].as_str())
                        .all(is_supported_package);
                    are_all_supported_packages
                } else {
                    false
                }
            });

            match supported_packages {
                Some(true) => {}
                _ => {
                    // bail!("The SBOM contains package type(s) not supported by Dependency Analytics. The Dependency Analytics report may be unavailable for this SBOM.")
                }
            }
        }
    }

    Ok(sbom)
}

#[function_component(Scanner)]
pub fn scanner() -> Html {
    let analytics = use_analytics();
    let content = use_state_eq(|| None::<Rc<String>>);
    let onsubmit = use_callback(content.clone(), |data, content| content.set(Some(data)));

    let sbom = use_memo(content.clone(), |content| {
        content.as_ref().and_then(|data| {
            parse_and_validate(data.as_bytes())
                .ok()
                .map(|sbom| (data.clone(), Rc::new(sbom)))
        })
    });

    let onvalidate = use_callback(analytics.clone(), |data: Rc<String>, analytics| {
        let result = parse_and_validate(data.as_bytes());
        analytics.track(ParseOutcome(&result));
        match result {
            Ok(_sbom) => Ok(data),
            Err(err) => Err(format!("Failed to parse SBOM: {err}")),
        }
    });

    // allow resetting the form
    let onreset = use_callback((content.clone(), analytics.clone()), move |_, (content, analytics)| {
        content.set(None);
        analytics.track(Reset);
    });

    let config = use_config_private();

    match &*sbom {
        Some((raw, _bom)) => {
            html!(<Inspect {onreset} raw={(*raw).clone()} />)
        }
        None => {
            html!(
                <>
                    <CommonHeader />

                    if let Some(hint) = &config.scanner.welcome_hint {
                        <HintView hint_key={Hints::ScannerWelcome} hint={hint.clone()} />
                    }

                    <PageSection variant={PageSectionVariant::Light} fill=true>
                        <Upload {onsubmit} {onvalidate} />
                    </PageSection>
                </>
            )
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct CommonHeaderProperties {
    #[prop_or_default]
    pub onreset: Option<Callback<()>>,
}

#[function_component(CommonHeader)]
fn common_header(props: &CommonHeaderProperties) -> Html {
    let config = use_config_private();
    let analytics = use_analytics();

    let onlearn = use_tracking(|_, _| ClickLearn, ());
    let onreset = use_map(props.onreset.clone(), move |callback| {
        callback.reform(|_| ()).wrap_tracking(analytics.clone(), |_| Reset)
    });

    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Scan an SBOM"}</Title>
                        <p>
                            {"Load an existing CycloneDX (1.3, 1.4, 1.5) or SPDX (2.2, SPDX 2.3) file"}
                            if let Some(url) = &config.scanner.documentation_url {
                                {" or "}
                                <a
                                    href={url.to_string()} target="_blank"
                                    class="pf-v5-c-button pf-m-link pf-m-inline"
                                    onclick={onlearn}
                                >
                                    {"learn about creating an SBOM"}
                                </a>
                            }
                            { "." }
                        </p>
                    </Content>
                </FlexItem>
                <FlexItem modifiers={[FlexModifier::Align(Alignment::Right), FlexModifier::Align(Alignment::End)]}>
                    if let Some(onreset) = onreset {
                        <Button
                            label={"Scan another"}
                            icon={Icon::Redo}
                            variant={ButtonVariant::Secondary}
                            onclick={onreset}
                        />
                    }
                </FlexItem>
            </Flex>
        </PageSection>
    )
}
