# VTPipeline

A pipeline for querying/downloading hashes, scan reports, and files from VirusTotal. This package implements the methodology used to build the [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024/) dataset.

## Installation
```
git clone 
cd vtpipeline-rs/
cargo build --release
```

## Setup


#### Basic configuration
To get started, create a config file for VTPipeline. An example can be found in example/vt.toml. Set data_dir to the path where you want your base directory to be, and set vt_api_key to your VirusTotal API key.

```
data_dir = "/path/to/base"
vt_api_key = "aabbcc"
```

VTPipeline searches for the config file in ```/etc/vtpipeline/``` by default, or you can pass it as a command-line argument.


#### Configuring file thresholds
You can configure which types of files you want to query. A default list of files, and how many of each to query on a given day, is located in data/file_thresholds.json


#### Configuring supported antivirus products
A list of default-supported antivirus products is located in data/avs.json. It also lists if there are any AV products with known relationships to other AVs.


## Query hashes from VirusTotal
Use the ```vtpipeline hashes``` command to query hashes of files that were first uploaded to VirusTotal within the last 24 hours, or 90 days ago.

```
vtpipeline hashes --date-offset 1
```

## Query scans and files from VirusTotal

After querying hashes from VirusTotal, you can retrieve scans and download files using the ```vtpipeline scans``` command.

```
vtpipeline scans --date-offset 90
```

The TLSH fuzzy hash was used to identify and down-sample near-duplicate files before downloading them. This is not exactly the same as the EMBER2024 dataset implementation, which entirely removes near-duplicates.

```
vtpipeline scans --date-offset 90 --diff-threshold 30
```


