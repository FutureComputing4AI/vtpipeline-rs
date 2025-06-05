use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use clap::builder::OsStr;
use serde::Deserialize;

/// Relationship between antivirus products
/// The key is an antivirus product.
/// The value is an optional list of related antivirus products.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AVs(pub HashMap<String, Option<HashSet<String>>>);

impl AVs {
    /// Return normalized version of AV product name
    ///
    /// ```rust
    /// use vtpipeline::config::AVs;
    ///
    /// assert_eq!(AVs::normalize_av("TrendMicro-HouseCall"), "trendmicrohousecall".to_string());
    /// ```
    pub fn normalize_av<A: AsRef<str>>(av: A) -> String {
        av.as_ref()
            .to_lowercase()
            .replace([' ', '-', '_'], "")
            .trim()
            .to_string()
    }

    /// Set of supported AV products, strings are reference to original AV string.
    pub fn supported_avs(&self) -> HashSet<&String> {
        HashSet::from_iter(self.0.keys())
    }

    /// Map of AV to Set of correlated AVs, including itself. Has reference to original AV string.
    pub fn correlated_avs(&self) -> HashMap<&String, HashSet<&String>> {
        let mut map = HashMap::with_capacity(self.0.len());
        for (av, av_correlated) in self.0.iter() {
            let mut correlated = HashSet::with_capacity(av_correlated.as_ref().iter().count() + 1);
            if let Some(avs) = av_correlated {
                correlated.extend(avs);
            }
            correlated.insert(av);
            map.insert(av, correlated);
        }
        map
    }
}

impl Default for AVs {
    fn default() -> Self {
        const DATA: &str = include_str!("../data/avs.json");
        serde_json::from_str::<Self>(DATA).expect("failed to parse built-in AV data")
    }
}

impl Display for AVs {
    /// Hack: Get `clap::Arg` to allow having a default for `AVs` which uses the `Default` trait,
    /// but we don't want to display it because it's not useful.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl From<AVs> for OsStr {
    /// Hack: Get `clap::Arg` to allow having a default for `AVs` which uses the `Default` trait,
    /// but we don't want to display it because it's not useful.
    fn from(_value: AVs) -> Self {
        "".into()
    }
}

impl FromStr for AVs {
    type Err = anyhow::Error;

    /// For use with [clap::Arg], we expect that the string will be a path to the AVs JSON file,
    /// but `Clap` wants a string and assumes this is the string version of the data, but really
    /// it is the path.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(Self::default())
        } else {
            let path = PathBuf::from_str(s)?;
            let contents = std::fs::read_to_string(path)?;
            let avs: Self = serde_json::from_str::<Self>(&contents)
                .context(format!("failed to parse AV data from json file {s}"))?;
            Ok(avs)
        }
    }
}

/// Limitations for all files of interest
/// Key is the file type
/// Value is the maximum amount of files to download
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FileTypeThresholds(pub HashMap<String, u32>);

impl Default for FileTypeThresholds {
    fn default() -> Self {
        const DATA: &str = include_str!("../data/file_thresholds.json");
        serde_json::from_str::<Self>(DATA)
            .expect("failed to parse built-in file type threshold data")
    }
}

impl Display for FileTypeThresholds {
    /// Hack: Get `clap::Arg` to allow having a default for `FileTypeThresholds` which uses the
    /// `Default` trait, but we don't want to display it because it's not useful.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl From<FileTypeThresholds> for OsStr {
    /// Hack: Get `clap::Arg` to allow having a default for `FileTypeThresholds` which uses the
    /// `Default` trait, but we don't want to display it because it's not useful.
    fn from(_value: FileTypeThresholds) -> Self {
        "".into()
    }
}

impl FromStr for FileTypeThresholds {
    type Err = anyhow::Error;

    /// For use with [clap::Arg], we expect that the string will be a path to the File Type
    /// Thresholds JSON file, but `Clap` wants a string and assumes this is the string version
    /// of the data, but really it is the path.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(Self::default())
        } else {
            let path = PathBuf::from_str(s)?;
            let contents = fs::read_to_string(path)?;
            let avs: Self = serde_json::from_str::<Self>(&contents)
                .context(format!("failed to parse AV data from json file {s}"))?;
            Ok(avs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_avs() {
        let default_avs = AVs::default();
        assert_eq!(default_avs.0.len(), 100);
    }

    #[test]
    fn default_thresholds() {
        let default_thresholds = FileTypeThresholds::default();
        assert_eq!(default_thresholds.0.len(), 16);
    }
}
