#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]

/// Data structures for configuration of the pipeline
pub mod config;

use config::{AVs, FileTypeThresholds};

use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, TimeDelta, Timelike, Utc};
use clap::{Args, Subcommand};
use dashmap::DashMap;
use malwaredb_virustotal::common::ReportResponseHeader;
use malwaredb_virustotal::filereport::ScanResultAttributes;
use malwaredb_virustotal::filesearch::flags::{FileType, FirstSubmission, Tag};
use malwaredb_virustotal::VirusTotalClient;
use rand::seq::IteratorRandom;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tlsh_fixed::Tlsh;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Alias for the file response, keep the data as someone would get if they called
/// the file detail endpoint manually
pub type VtFileReport = ReportResponseHeader<ScanResultAttributes>;

/// Constructed version of the VirusTotal Pipeline
pub const VERSION: &str = concat!(
    "v",
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_DESCRIBE"),
    " ",
    env!("VERGEN_BUILD_DATE")
);

/// Only search for hashes of file type we're interested in. The [FileType] and [Option<Tag>] pairs
/// needs to match the file types used with [TypePair] as that is how data is saved to disk.
pub const INTERESTING_FILE_TYPES: [(FileType, Option<Tag>, &str); 15] = [
    (FileType::Apk, None, "Android"),
    (FileType::Elf, None, "ELF"),
    (FileType::MachO, None, "macOS"),
    (FileType::Doc, None, "Word"),
    (FileType::Docx, None, "WordX"),
    (FileType::Xls, None, "Excel"),
    (FileType::Xlsx, None, "ExcelX"),
    (FileType::Pdf, None, "PDF"),
    (FileType::PE32, None, "PE32"),
    (FileType::PE32, Some(Tag::DotNetAssembly), ".Net"),
    (FileType::PE32, Some(Tag::Executable64bit), "PE32 64-bit"),
    (FileType::Rtf, None, "RTF"),
    (FileType::Ppt, None, "PowerPoint"),
    (FileType::Pptx, None, "PowerPointX"),
    (FileType::Script, None, "Scripts"),
];

/// For the hash map containing hashes of samples with some amount of AV hits: none
pub const ZERO_AVS: &str = "0";

/// For the hash map containing hashes of samples with some amount of AV hits: 1-4
pub const ONE_TO_FOUR_AVS: &str = "1to4";

/// For the hash map containing hashes of samples with some amount of AV hits: 5+
pub const FIVE_PLUS_AVS: &str = "5plus";

/// File name for hashes, includes file type
pub const HASHES_FILE: &str = "hashes.json";

/// File name for logs, per date of fetched hashes or reports
pub const LOG_FILE: &str = "logs.txt";

/// File type and tag for sub-type, relates to what's in [INTERESTING_FILE_TYPES]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TypePair {
    /// File type
    pub ftype: FileType,

    /// VirusTotal tag as sub-type
    pub tag: Option<Tag>,
}

impl TypePair {
    /// Get a string suitable for indexing into [FileTypeThresholds], relates to [INTERESTING_FILE_TYPES]
    pub fn to_filetype_for_thresholds(&self) -> &'static str {
        match (self.ftype, self.tag) {
            (FileType::Apk, None) => "APK",
            (FileType::Elf, None) => "ELF",
            (FileType::Elf, Some(Tag::Executable64bit)) => "ELF64",
            (FileType::MachO, None) => "Mach-O",
            (FileType::Doc, None) => "DOC",
            (FileType::Docx, None) => "DOCX",
            (FileType::Xls, None) => "XLS",
            (FileType::Xlsx, None) => "XLSX",
            (FileType::Pdf, None) => "PDF",
            (FileType::PE32, Some(Tag::DotNetAssembly)) => ".NET",
            (FileType::PE32, None) => "Win32",
            (FileType::PE32, Some(Tag::Executable64bit)) => "Win64",
            (FileType::Rtf, None) => "RTF",
            (FileType::Ppt, None) => "PPT",
            (FileType::Pptx, None) => "PPTX",
            (FileType::Script, None) => "Script",

            // We don't want a directory called Unknown, we want to catch this error.
            _ => unreachable!(),
        }
    }
}

impl Serialize for TypePair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(tag) = self.tag {
            use serde::ser::Error;

            let file_name = match serde_variant::to_variant_name(&self.ftype) {
                Ok(s) => s,
                Err(e) => return Err(Error::custom(e)),
            };
            let file_tag = match serde_variant::to_variant_name(&tag) {
                Ok(s) => s,
                Err(e) => return Err(Error::custom(e)),
            };
            serializer.serialize_str(&format!("{}_{}", file_name, file_tag))
        } else {
            self.ftype.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for TypePair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let typepair = if s.contains("_") {
            let (ftype, tag) = s.split_once("_").unwrap();
            let ftype: FileType = FileType::deserialize(ftype.into_deserializer())?;
            let tag: Tag = Tag::deserialize(tag.into_deserializer())?;
            TypePair {
                ftype,
                tag: Some(tag),
            }
        } else {
            let ftype: FileType = FileType::deserialize(s.into_deserializer())?;
            TypePair { ftype, tag: None }
        };

        Ok(typepair)
    }
}

impl From<(FileType, Option<Tag>)> for TypePair {
    fn from(tp: (FileType, Option<Tag>)) -> Self {
        TypePair {
            ftype: tp.0,
            tag: tp.1,
        }
    }
}

impl From<TypePair> for String {
    fn from(value: TypePair) -> Self {
        if let Some(tag) = value.tag {
            format!("{}_{}", value.ftype, tag)
        } else {
            value.ftype.to_string()
        }
    }
}

impl Display for TypePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = if let Some(tag) = self.tag {
            format!("{}_{}", self.ftype, tag)
        } else {
            self.ftype.to_string()
        };
        write!(f, "{}", str)
    }
}

/// Hashes stored by file type
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HashByType {
    /// Hashes stored by type
    #[serde(flatten)]
    pub inner: HashMap<TypePair, HashSet<String>>,
}

impl HashByType {
    /// Get the total amount of hashes
    #[inline]
    pub fn num_items(&self) -> usize {
        self.inner.values().map(|v| v.len()).sum()
    }

    /// Indicates if there aren't any hashes
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// VirusTotal Pipeline Object
pub struct VTPipeline {
    /// Data directory for storing hashes, reports, and binaries
    pub data_dir: PathBuf,

    /// VT API client object
    pub client: Arc<VirusTotalClient>,

    /// Action to be performed
    pub action: PipelineAction,
}

impl VTPipeline {
    /// Create the VTPipeline object from configuration components
    pub fn new(data_dir: PathBuf, action: PipelineAction, client: VirusTotalClient) -> Self {
        Self {
            data_dir,
            client: Arc::new(client),
            action,
        }
    }
}

/// VirusTotal Pipeline Object
#[derive(Deserialize)]
pub struct PipelineConfiguration {
    /// Base directory for hashes, logs, samples, etc.
    pub data_dir: PathBuf,

    /// Virus Total API key
    #[serde(flatten)]
    pub vt_key: VirusTotalClient,
}

impl Debug for VTPipeline {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "data_dir: {:?}, action: {:?}",
            self.data_dir, self.action
        )
    }
}

/// Indicate the action to be performed: get hashes for file types of interest or fetch VT reports
#[derive(Subcommand, Clone, Debug, PartialEq, Deserialize)]
pub enum PipelineAction {
    /// Fetch hashes for this time `X` days ago
    Hashes(GetHashes),

    /// Fetch AV information and samples
    Scans(DailyScans),
}

/// When getting hashes from VT, we need the offset specified as number of days: 1 or 90.
#[derive(Clone, Debug, PartialEq, Args, Deserialize)]
pub struct GetHashes {
    /// Days since the file was first seen, options are: 1, 90.
    #[arg(long, default_value_t = DayOffsets::One)]
    pub date_offset: DayOffsets,
}

/// When getting daily reports, parse some options relating to how we handle this data and decide
/// which files to keep
#[derive(Clone, Debug, PartialEq, Args, Deserialize)]
pub struct DailyScans {
    /// Days since the file was first seen, options are: 1, 90.
    #[arg(long, default_value_t = DayOffsets::One)]
    pub date_offset: DayOffsets,

    /// Size of the TLSH sketch window
    #[arg(long, default_value_t = 16)]
    pub sketch_window: u8,

    /// Max TLSH distance for files to be considered near duplicates
    #[arg(long, default_value_t = 10)]
    pub diff_threshold: u8,

    /// Number of threads to use
    #[arg(long, default_value_t = 4)]
    pub num_threads: u8,

    /// Path to the file with correlated antivirus products, if not using the default
    #[arg(long, default_value = AVs::default(), hide_default_value = true)]
    #[serde(default)]
    pub av_file: AVs,

    /// Path to the file with file type thresholds, if not using the default
    #[arg(long, default_value = FileTypeThresholds::default(), hide_default_value = true)]
    #[serde(default)]
    pub file_type_thresholds: FileTypeThresholds,
}

/// Day offsets are 1 or 90, this makes it easier to parse with Clap
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(u8)]
pub enum DayOffsets {
    /// VirusTotal data from one day ago
    #[default]
    One,

    /// VirusTotal data from 90 days ago, and download the samples
    Ninety,
}

impl<'de> Deserialize<'de> for DayOffsets {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let days: u8 = Deserialize::deserialize(deserializer)?;
        let days = match days {
            1 => DayOffsets::One,
            90 => DayOffsets::Ninety,
            d => {
                return Err(serde::de::Error::custom(format!(
                    "invalid day offset {}",
                    d
                )))
            }
        };

        Ok(days)
    }
}

impl From<DayOffsets> for u8 {
    fn from(val: DayOffsets) -> Self {
        match val {
            DayOffsets::One => 1,
            DayOffsets::Ninety => 90,
        }
    }
}

impl FromStr for DayOffsets {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "1" => Ok(Self::One),
            "90" => Ok(Self::Ninety),
            _ => Err("Invalid option"),
        }
    }
}

impl Display for DayOffsets {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::One => write!(f, "1"),
            Self::Ninety => write!(f, "90"),
        }
    }
}

impl VTPipeline {
    /// Run the pipeline based on the user's configuration and method (scans vs hashes)
    pub async fn run(&self) -> Result<()> {
        ensure!(
            self.data_dir.is_dir(),
            "{:?} is not a directory or doesn't exist",
            self.data_dir
        );

        let date_dir = self.date_dir();
        let timestamp = self.utc_time();

        match &self.action {
            PipelineAction::Hashes(_hashes) => {
                if !date_dir.exists() {
                    fs::create_dir_all(&date_dir)
                        .context(format!("failed to create directory {date_dir:?}"))?;
                }

                let mut hashes_types = HashByType::default();
                for start_second in (0..60u32).step_by(5) {
                    let start = timestamp.clone().with_second(start_second).unwrap();
                    let end = timestamp.clone().with_second(start_second + 4).unwrap();

                    let first_seen = FirstSubmission::from_datetime(start).until_date(end);
                    for (ftype, type_tag, file_name) in INTERESTING_FILE_TYPES {
                        let type_query = if let Some(tag) = type_tag {
                            ftype + tag
                        } else {
                            ftype.to_string()
                        };
                        let search_results = self
                            .client
                            .search(first_seen.clone() + type_query)
                            .await
                            .context(format!("Searching for hashes for {file_name} files"))?;
                        info!(
                            "Received {} hashes for {ftype} tag {type_tag:?} for range {start} to {end}",
                            search_results.hashes.len()
                        );
                        if !search_results.hashes.is_empty() {
                            hashes_types
                                .inner
                                .entry((ftype, type_tag).into())
                                .or_default()
                                .extend(search_results.hashes);
                        }
                    }
                }

                if hashes_types.is_empty() {
                    bail!("Failed to get hashes from VirusTotal!");
                }

                let hashes_file = date_dir.join(HASHES_FILE);
                fs::write(
                    &hashes_file,
                    serde_json::to_string_pretty(&hashes_types)
                        .context("failed to convert to json")?
                        .as_bytes(),
                )?;

                let mut log_file = fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(date_dir.join(LOG_FILE))?;
                let time_now = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                log_file.write_all(
                    format!(
                        "{time_now}\tWrote {} hashes to {hashes_file:?}\n",
                        hashes_types.num_items()
                    )
                    .as_bytes(),
                )?;
                log_file.flush()?;

                Ok(())
            }
            PipelineAction::Scans(scans) => {
                // This script expects to be run at 01:00 UTC each day
                // Since the day has just ended, we need to subtract 1 from the date to get
                // the hashes which we just finished querying
                if !date_dir.is_dir() {
                    bail!("Date directory {date_dir:?} does not exist!");
                }

                let log_file = date_dir.join(LOG_FILE);
                let hash_file = date_dir.join(HASHES_FILE);
                let download_hash_file_path = date_dir.join("download_hashes.txt");
                let scan_file = date_dir.join(format!("vt_scans_{}day.jsonl", scans.date_offset));
                let submissions_file = date_dir.join("submissions.jsonl");

                let supported_avs = scans.av_file.supported_avs();
                let correlated_avs = scans.av_file.correlated_avs();
                let mut unknown_avs: HashMap<String, u32> = HashMap::new();

                let hashes_string = fs::read_to_string(&hash_file)
                    .context(format!("failed to reach hashes file {hash_file:?}"))?;
                let hashes_types = serde_json::from_str::<HashByType>(&hashes_string)?;

                let reports_by_type = Arc::new(DashMap::<TypePair, Vec<VtFileReport>>::new());
                for (file_type, hashes) in hashes_types.inner.iter() {
                    reports_by_type.insert(*file_type, Vec::new());
                    self.get_vt_scans(
                        // TODO: Don't copy
                        hashes.iter().cloned().collect(),
                        scan_file.clone(),
                        file_type,
                        &reports_by_type,
                        &log_file,
                        scans.num_threads as usize,
                    )
                    .await?;
                }
                info!("Finished querying VirusTotal for scans");

                // Read hashes and TLSH digests from scan file
                // Keep track of file hashes with amount of AV hits (none, 1-4, 5+)
                let mut file_type_hashes: HashMap<TypePair, HashSet<String>> = HashMap::new();
                let mut av_count_hashes: HashMap<&'static str, HashSet<String>> = HashMap::new();
                av_count_hashes.insert(ZERO_AVS, HashSet::new());
                av_count_hashes.insert(ONE_TO_FOUR_AVS, HashSet::new());
                av_count_hashes.insert(FIVE_PLUS_AVS, HashSet::new());

                let mut hash_tlshs = HashMap::new();
                for type_reports in reports_by_type.iter() {
                    let file_type = type_reports.key();

                    for report in type_reports.value() {
                        if report.attributes.tlsh.is_none()
                            || report.attributes.last_analysis_results.is_empty()
                        {
                            continue;
                        }

                        let tlsh = report.attributes.tlsh.clone().unwrap();
                        file_type_hashes
                            .entry(*file_type)
                            .or_default()
                            .insert(report.attributes.sha256.clone());

                        hash_tlshs.insert(report.attributes.sha256.clone(), tlsh.clone());

                        let mut num_detections = 0u32;
                        let mut seen_avs = HashSet::new();
                        for (av_name, scan) in &report.attributes.last_analysis_results {
                            if scan.result.is_none() {
                                continue;
                            }

                            let av_name = AVs::normalize_av(av_name);
                            if !supported_avs.contains(&av_name) {
                                *unknown_avs.entry(av_name).or_default() += 1u32;
                                continue;
                            }

                            // Only count AV's that haven't been seen, and none of their correlated AV's have either
                            let corr_avs = &correlated_avs[&av_name];
                            let mut corr_av_seen = false;
                            for av in corr_avs {
                                if seen_avs.contains(*av) {
                                    corr_av_seen = true;
                                    break;
                                }
                            }

                            // If none of the correlated AV's were seen, add the current AV and all the correlated ones to the list of seen AV's, and increment the number of detections
                            if !corr_av_seen {
                                num_detections += 1;
                                seen_avs.insert(av_name);
                                //seen_avs.extend(&*corr_avs);
                            }
                        }

                        match num_detections {
                            0 => {
                                av_count_hashes
                                    .get_mut(ZERO_AVS)
                                    .unwrap()
                                    .insert(report.attributes.sha256.clone());
                            }
                            1..=4 => {
                                av_count_hashes
                                    .get_mut(ONE_TO_FOUR_AVS)
                                    .unwrap()
                                    .insert(report.attributes.sha256.clone());
                            }
                            _ => {
                                av_count_hashes
                                    .get_mut(FIVE_PLUS_AVS)
                                    .unwrap()
                                    .insert(report.attributes.sha256.clone());
                            }
                        }
                    }
                }

                let mut sketch_hashes: HashMap<String, Vec<String>> = HashMap::new();
                for (sha256, tlsh) in hash_tlshs.iter() {
                    for i in 0..tlsh.len() - scans.sketch_window as usize {
                        let sketch = tlsh[i..i + scans.sketch_window as usize].to_string();

                        if let Some(hash_list) = sketch_hashes.get_mut(sha256) {
                            hash_list.push(sha256.clone());
                        } else {
                            sketch_hashes.insert(sketch, vec![sha256.clone()]);
                        }
                    }
                }

                // Identify hashes of files which are near-duplicates
                let mut hash_dups: HashMap<String, HashSet<String>> =
                    HashMap::with_capacity(hash_tlshs.len());
                for hash in hash_tlshs.keys() {
                    hash_dups.insert(hash.clone(), HashSet::new());
                }

                for hashes in sketch_hashes.values() {
                    if hashes.len() <= 1 {
                        continue;
                    }
                    for hash1 in hashes.iter() {
                        let tlsh1 = match Tlsh::from_str(hash_tlshs.get(hash1).unwrap()) {
                            Ok(h) => h,
                            Err(e) => {
                                error!("Failed to parse TLSH {e} for hash {hash1}: {e}");
                                continue;
                            }
                        };

                        for hash2 in hashes.iter().skip(1) {
                            let tlsh2 = match Tlsh::from_str(hash_tlshs.get(hash2).unwrap()) {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("Failed to parse TLSH {e} for hash {hash2}: {e}");
                                    continue;
                                }
                            };
                            let diff = tlsh1.diff(&tlsh2, false);
                            if diff <= scans.diff_threshold as usize {
                                hash_dups.get_mut(hash1).expect("").insert(hash2.clone());
                            }
                        }
                    }
                }

                // Form graph where files are nodes and near-duplicates have edges between
                // them. Identify connected components of the graph, then choose 10%
                // of files in each component to keep (min 1 file per component).
                let mut keep_sha256s: HashSet<String> = HashSet::new();
                let mut remaining_sha256s: HashSet<String> =
                    HashSet::from_iter(hash_tlshs.keys().cloned());
                let mut rng = rand::rng();
                for sha256 in hash_tlshs.keys() {
                    if !remaining_sha256s.contains(sha256) {
                        continue;
                    }

                    // Recursively identify subgraph of the current file
                    let mut component = HashSet::new();
                    let mut hash_queue = vec![sha256.clone()];
                    loop {
                        if hash_queue.is_empty() {
                            break;
                        }

                        let cur_sha256 = hash_queue.pop().unwrap();
                        if component.contains(&cur_sha256) {
                            continue;
                        }
                        hash_queue.extend(hash_dups.get(&cur_sha256).unwrap().clone());
                        component.insert(cur_sha256);
                    }

                    // Randomly sample 10% of hashes (min 1)
                    let num_files = max(component.len() / 10, 1);
                    keep_sha256s.extend(
                        component
                            .iter()
                            .choose_multiple(&mut rng, num_files)
                            .iter()
                            .map(|s| s.to_string()),
                    );

                    // We're done with all of the hashes in this component now
                    remaining_sha256s.retain(|s| !component.contains(s));
                }
                info!("End for sha256 in hash_tlshs");

                // Log how many hashes we de-duplicated
                {
                    let mut log_file = fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&log_file)
                        .context(format!("failed to open log file {log_file:?} for append"))?;
                    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S");
                    let orig_n_hashes = hash_tlshs.keys().len();
                    let keep_n_hashes = keep_sha256s.len();
                    // TODO: This should use the logging crate
                    writeln!(
                        log_file,
                        "{now}\tDeduped from {orig_n_hashes} -> {keep_n_hashes} hashes"
                    )?;
                    log_file.flush()?;
                }

                // Split files by file type
                let mut download_hashes = HashSet::new();
                for (file_type, hashes) in &file_type_hashes {
                    // Select only the de-duplicated hashes of the current file type
                    let mut dedup_hashes: Vec<String> =
                        hashes.intersection(&keep_sha256s).cloned().collect();
                    let num_keep = if let Some(num) = scans
                        .file_type_thresholds
                        .0
                        .get(file_type.to_filetype_for_thresholds())
                    {
                        *num as usize
                    } else {
                        warn!("Skipping file type {file_type} (aka {}) as it is not in the thresholds file", file_type.to_filetype_for_thresholds());
                        0
                    };

                    if num_keep == 0 {
                        continue;
                    }

                    // Downsample to the number of files to keep for this file type
                    if dedup_hashes.len() > num_keep {
                        dedup_hashes = dedup_hashes
                            .iter()
                            .choose_multiple(&mut rng, num_keep)
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                    }
                    download_hashes.extend(dedup_hashes);
                }

                if scans.date_offset == DayOffsets::Ninety {
                    // Write hashes to file
                    let mut download_hash_file = fs::OpenOptions::new()
                        .truncate(false)
                        .create(true)
                        .write(true)
                        .open(&download_hash_file_path)
                        .context(format!(
                            "failed to open downloaded hashes file {download_hash_file_path:?}"
                        ))?;
                    for hash in &download_hashes {
                        writeln!(download_hash_file, "{hash}")?;
                    }
                    download_hash_file.flush()?;

                    {
                        let mut log_file = fs::OpenOptions::new()
                            .truncate(false)
                            .append(true)
                            .create(true)
                            .open(&log_file)
                            .context(format!("failed to open log file {log_file:?} for append"))?;
                        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S");
                        let n_hashes = download_hashes.len();
                        // TODO: This should use the logging crate
                        writeln!(
                            log_file,
                            "{}\tWrote {} hashes to {download_hash_file_path:?}",
                            now, n_hashes,
                        )?;
                        log_file.flush()?;

                        let mut submissions_file = fs::OpenOptions::new()
                            .truncate(false)
                            .create(true)
                            .append(true)
                            .open(&submissions_file)
                            .context(format!(
                                "failed to open submissions file {submissions_file:?}"
                            ))?;

                        // Download the files in download_hashes.txt
                        for (file_type, file_hashes) in file_type_hashes {
                            // Select only hashes of the current file type from download_hashes.txt
                            let file_hashes: HashSet<String> = file_hashes
                                .intersection(&download_hashes)
                                .cloned()
                                .collect();

                            for (num_detect, av_hashes) in av_count_hashes.iter() {
                                // Select only the hashes with a certain range of AV detections
                                let keep_hashes: HashSet<String> =
                                    file_hashes.intersection(av_hashes).cloned().collect();
                                let num_detect_path = match *num_detect {
                                    ZERO_AVS => "benign",
                                    ONE_TO_FOUR_AVS => "unknown",
                                    FIVE_PLUS_AVS => "malicious",
                                    _ => unreachable!(),
                                };
                                let dir_path = date_dir
                                    .join::<String>(file_type.to_filetype_for_thresholds().into())
                                    .join(num_detect_path);
                                fs::create_dir_all(&dir_path)?;

                                for sha256 in keep_hashes {
                                    let contents = match self.client.download(&sha256).await {
                                        Ok(c) => c,
                                        Err(e) => {
                                            error!("Failed to download {sha256}: {e}");
                                            continue;
                                        }
                                    };
                                    let file_path = dir_path.join(&sha256);
                                    if let Err(e) = fs::write(&file_path, contents) {
                                        error!("Failed to save {sha256}: {e}");
                                        continue;
                                    }

                                    let submissions = self.submissions(&sha256).await?;
                                    writeln!(submissions_file, "{submissions}")?;
                                }
                            }
                        }
                    }
                }

                Ok(())
            }
        }
    }

    /// Get the UTC timestamp from offset for querying VirusTotal
    fn utc_time(&self) -> DateTime<Utc> {
        let now = Utc::now();
        let delta = match &self.action {
            PipelineAction::Hashes(hashes) => TimeDelta::days(hashes.date_offset as i64),
            PipelineAction::Scans(scans) => TimeDelta::days(scans.date_offset as i64),
        };
        now - delta
    }

    /// Get the UTC timestamp from offset for querying VirusTotal
    fn date_dir(&self) -> PathBuf {
        self.data_dir
            .join(self.utc_time().format("%Y-%m-%d").to_string())
    }

    /// Get the submissions information for a file
    async fn submissions(&self, hash: &str) -> Result<String> {
        let response = self
            .client
            .other(&format!("files/{hash}/submissions"))
            .await?;
        String::from_utf8(response.to_ascii_lowercase()).context("failed to decode ascii")
    }

    async fn get_vt_scans(
        &self,
        hashes: Vec<String>,
        scan_file: PathBuf,
        file_type: &TypePair,
        types_reports: &Arc<DashMap<TypePair, Vec<VtFileReport>>>,
        log_file: &Path,
        threads: usize,
    ) -> Result<()> {
        let hashes = Arc::new(hashes);
        let scan_file_arc = Arc::new(scan_file);
        let mut thread_handles = Vec::with_capacity(threads);
        let file_counter = Arc::new(AtomicUsize::default());
        let file_type = Arc::new(*file_type);
        let mut log_file_handle = fs::OpenOptions::new()
            .truncate(false)
            .append(true)
            .create(true)
            .open(log_file)
            .context(format!("failed to open log file {log_file:?} for append"))?;
        let scan_file_lock = Arc::new(RwLock::new(
            fs::OpenOptions::new()
                .truncate(false)
                .append(true)
                .create(true)
                .open(scan_file_arc.as_path())
                .context(format!(
                    "failed to open scan results file {scan_file_arc:?} for append"
                ))?,
        ));

        for _ in 0..threads {
            let local_counter = file_counter.clone();
            let local_hashes = hashes.clone();
            let local_scan_file_lock = scan_file_lock.clone();
            let local_scan_file_arc = scan_file_arc.clone();
            let local_client = self.client.clone();
            let local_types_reports = types_reports.clone();
            let local_file_type = file_type.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let current_index = local_counter.fetch_add(1, Ordering::Relaxed);
                    let hash = if let Some(h) = local_hashes.get(current_index) {
                        h
                    } else {
                        break;
                    };

                    match local_client.get_file_report(hash).await {
                        Ok(report) => {
                            let mut file_handle = local_scan_file_lock.write().await;

                            let report_bytes = match serde_json::to_string(&report) {
                                Ok(r) => {
                                    // Prevent unneeded copy
                                    local_types_reports
                                        .get_mut(&local_file_type)
                                        .unwrap()
                                        .push(report);
                                    r
                                }
                                Err(e) => {
                                    // Prevent unneeded copy
                                    local_types_reports
                                        .get_mut(&local_file_type)
                                        .unwrap()
                                        .push(report);
                                    error!("Failed to serialize report for {local_file_type}: {e}");
                                    continue;
                                }
                            };

                            if file_handle.write_all(report_bytes.as_bytes()).is_err() {
                                eprintln!("failed to write report to {local_scan_file_arc:?}");
                            }
                            if file_handle.write_all(b"\n").is_err() {
                                eprintln!("failed to write newline to {local_scan_file_arc:?}")
                            }
                        }
                        Err(err) => {
                            eprintln!("VirusTotal error: {err}");
                            break;
                        }
                    }
                }
            });
            thread_handles.push(handle);
        }

        for handle in thread_handles {
            handle.await?;
        }

        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        log_file_handle
            .write_all(
                format!(
                    "{now}\tWrote {} scans to {scan_file_arc:?}\n",
                    file_counter.load(Ordering::Relaxed) - threads
                )
                .as_bytes(),
            )
            .context(format!("failed to write log to {log_file:?}"))?;

        Ok(())
    }
}
