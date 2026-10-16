//! Compact, bounded domain indexes shared by the app, benchmarks and fuzz target.
//! No network or filesystem access. Cache offsets are validated before indexing.
use std::io::Read;
const MAGIC: &[u8; 8] = b"BR-OISD\x01";
pub const MAX_LIST: usize = 32 * 1024 * 1024;
pub const MAX_CACHE: usize = 2 * (MAX_LIST + 4_000_004 + 332) + 16;
const MAX_DOMAINS: usize = 1_000_000;
type Result<T> = std::result::Result<T, String>;

pub struct List {
    pub modified: String,
    data: String,
    // One u32 per domain plus an end sentinel; no allocation per domain.
    offsets: Vec<u32>,
}
fn valid_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
impl List {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_LIST {
            return Err("OISD list exceeds 32 MiB.".into());
        }
        let modified = text
            .lines()
            .find_map(|line| line.strip_prefix("! Last modified:"))
            .unwrap_or("not provided")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        let lower = text.to_ascii_lowercase();
        let mut names = Vec::new();
        for line in lower.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('!') || line == "[adblock plus]" {
                continue;
            }
            let name = line
                .strip_prefix("||")
                .and_then(|s| s.strip_suffix('^'))
                .ok_or("Unsupported OISD rule format; the previous cache was kept.")?;
            if !valid_domain(name) {
                return Err("Invalid OISD domain rule; the previous cache was kept.".into());
            }
            if names.len() == MAX_DOMAINS {
                return Err("OISD list exceeds one million rules.".into());
            }
            names.push(name);
        }
        if names.is_empty() {
            return Err("OISD list contained no domain rules.".into());
        }
        names.sort_unstable();
        names.dedup();
        let mut data = String::with_capacity(names.iter().map(|name| name.len()).sum());
        let mut offsets = Vec::with_capacity(names.len() + 1);
        for name in names {
            offsets.push(data.len() as u32);
            data.push_str(name);
        }
        offsets.push(data.len() as u32);
        Ok(Self {
            modified,
            data,
            offsets,
        })
    }
    pub fn len(&self) -> usize {
        self.offsets.len() - 1
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn storage_bytes(&self) -> usize {
        self.data.len() + 4 * self.offsets.len() + self.modified.len()
    }
    fn at(&self, index: usize) -> &str {
        &self.data[self.offsets[index] as usize..self.offsets[index + 1] as usize]
    }
    /// `name` is a lowercase ASCII hostname without a trailing dot.
    /// Checks only label boundaries, including OISD whole-TLD rules.
    pub fn matching_domain<'a>(&'a self, name: &str) -> Option<&'a str> {
        let mut suffix = name;
        loop {
            if let Some(index) = self.index(suffix) {
                return Some(self.at(index));
            }
            suffix = suffix.split_once('.')?.1;
        }
    }
    fn index(&self, name: &str) -> Option<usize> {
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let mid = low + (high - low) / 2;
            match self.at(mid).cmp(name) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
    fn encode(&self, out: &mut Vec<u8>) {
        for value in [self.modified.len(), self.len(), self.data.len()] {
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        out.extend_from_slice(self.modified.as_bytes());
        for offset in &self.offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(self.data.as_bytes());
    }
    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Self> {
        let date_len = input.u32()? as usize;
        let count = input.u32()? as usize;
        let data_len = input.u32()? as usize;
        if date_len > 320 || count == 0 || count > MAX_DOMAINS || data_len > MAX_LIST {
            return Err("Invalid domain index lengths.".into());
        }
        let modified = input.string(date_len)?;
        if modified.chars().any(char::is_control) {
            return Err("Invalid cache date.".into());
        }
        let offsets = input.u32s(count + 1)?;
        let data = input.string(data_len)?;
        if offsets[0] != 0 || offsets[count] as usize != data_len {
            return Err("Invalid cache offsets.".into());
        }
        let mut previous = "";
        for pair in offsets.windows(2) {
            let domain = data
                .get(pair[0] as usize..pair[1] as usize)
                .ok_or("Invalid cache offsets.")?;
            if !valid_domain(domain)
                || domain.bytes().any(|b| b.is_ascii_uppercase())
                || domain <= previous
            {
                return Err("Invalid or unsorted cache domain.".into());
            }
            previous = domain;
        }
        Ok(Self {
            modified,
            data,
            offsets,
        })
    }
}

// Decode straight into final storage. The budget covers every heap buffer,
// including temporary rank validation, before allocation. No raw-file copy.
struct Decoder<R: Read> {
    reader: std::io::Take<R>,
    remaining: usize,
}
impl<R: Read> Decoder<R> {
    fn new(reader: R, size_limit: usize, memory_budget: usize) -> Self {
        Self {
            reader: reader.take(size_limit as u64 + 1),
            remaining: memory_budget,
        }
    }
    fn reserve(&mut self, size: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(size)
            .ok_or("Index exceeds the lookup memory budget.")?;
        Ok(())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.reader
            .read_exact(&mut bytes)
            .map_err(|_| "Truncated domain index cache.")?;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn string(&mut self, size: usize) -> Result<String> {
        self.reserve(size)?;
        let mut bytes = vec![0; size];
        self.reader
            .read_exact(&mut bytes)
            .map_err(|_| "Truncated domain index cache.")?;
        String::from_utf8(bytes).map_err(|_| "Invalid cache text.".into())
    }
    fn u32s(&mut self, count: usize) -> Result<Vec<u32>> {
        self.reserve(count.checked_mul(4).ok_or("Invalid index length.")?)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.u32()?);
        }
        Ok(values)
    }
    fn finish(&mut self) -> Result<()> {
        let mut byte = [0];
        match self.reader.read_exact(&mut byte) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            _ => Err("Unexpected trailing cache data or read error.".into()),
        }
    }
}
pub struct Snapshot {
    pub big: List,
    pub nsfw: List,
    pub downloaded: u64,
}
impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.big.storage_bytes() + self.nsfw.storage_bytes());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.downloaded.to_le_bytes());
        self.big.encode(&mut out);
        self.nsfw.encode(&mut out);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read_sized(bytes, bytes.len())
    }
    /// File size bounds decoded storage. The decoder also caps the stream in
    /// case the file grows after its metadata was read.
    pub fn read_sized(reader: impl Read, size: usize) -> Result<Self> {
        if size > MAX_CACHE {
            return Err("OISD cache exceeds size limit.".into());
        }
        Self::read_bounded(reader, size)
    }
    /// Stream from a bounded source into final storage; callers budget their
    /// own reader buffer separately. Returned indexes own no raw-file copy.
    pub fn read_bounded(reader: impl Read, memory_budget: usize) -> Result<Self> {
        let mut input = Decoder::new(reader, MAX_CACHE, memory_budget);
        if &input.array::<8>()? != MAGIC {
            return Err("Unknown OISD cache format; update the lists.".into());
        }
        let downloaded = u64::from_le_bytes(input.array()?);
        let big = List::decode(&mut input)?;
        let nsfw = List::decode(&mut input)?;
        input.finish()?;
        Ok(Self {
            big,
            nsfw,
            downloaded,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_roundtrip_truncation_and_corruption() {
        let db = Snapshot {
            big: List::parse("||z.example^\n||a.example^\n||A.example^").unwrap(),
            nsfw: List::parse("||xxx^").unwrap(),
            downloaded: 17,
        };
        let encoded = db.encode();
        let decoded = Snapshot::decode(&encoded).unwrap();
        assert_eq!(decoded.big.len(), 2);
        assert_eq!(
            decoded.big.matching_domain("sub.a.example"),
            Some("a.example")
        );
        assert_eq!(decoded.nsfw.matching_domain("sub.xxx"), Some("xxx"));
        for length in 0..encoded.len() {
            assert!(Snapshot::decode(&encoded[..length]).is_err());
        }
        let mut damaged = encoded.clone();
        damaged[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Snapshot::decode(&damaged).is_err());
        let mut extra = encoded;
        extra.push(0);
        assert!(Snapshot::decode(&extra).is_err());
    }
}

const RANK_MAGIC: &[u8; 8] = b"BR-RANK\x02";
pub const MAX_RANK_CSV: usize = 64 * 1024 * 1024;
pub const MAX_RANK_CACHE: usize = MAX_LIST + 8_000_004 + 512;

/// Sorted packed domains, with a parallel u32 rank array. Popularity is never
/// inherited as trust: callers must distinguish exact from parent matches.
pub struct Rankings {
    pub source_entries: u32,
    pub domains: List,
    ranks: Vec<u32>,
    pub list_id: String,
    pub downloaded: u64,
}
impl Rankings {
    pub fn parse(csv: &str, list_id: &str, source_date: &str, downloaded: u64) -> Result<Self> {
        if csv.len() > MAX_RANK_CSV {
            return Err("Tranco CSV exceeds 64 MiB.".into());
        }
        if list_id.is_empty()
            || list_id.len() > 32
            || !list_id.bytes().all(|c| c.is_ascii_alphanumeric())
            || source_date.len() > 80
            || source_date.chars().any(char::is_control)
        {
            return Err("Invalid Tranco metadata.".into());
        }
        let lower = csv.to_ascii_lowercase();
        let mut rows = Vec::new();
        let mut source_entries = 0;
        for line in lower.lines() {
            let (rank, name) = line.split_once(',').ok_or("Invalid Tranco CSV row.")?;
            let rank: u32 = rank.parse().map_err(|_| "Invalid Tranco rank.")?;
            if source_entries == MAX_DOMAINS || rank as usize != source_entries + 1 {
                return Err("Tranco ranks must be consecutive, starting at 1, with at most one million entries.".into());
            }
            source_entries += 1;
            if name.is_empty() || name.contains(',') || name.chars().any(char::is_control) {
                return Err("Malformed Tranco hostname field.".into());
            }
            if !valid_domain(name)
                || !name.contains('.')
                || name.parse::<std::net::IpAddr>().is_ok()
            {
                // The subdomain list includes DNS service records and other non-web names.
                // Keep published ranks intact while excluding names the inspector cannot visit.
                continue;
            }
            rows.push((name, rank));
        }
        if rows.is_empty() {
            return Err("Tranco CSV contains no domains.".into());
        }
        rows.sort_unstable_by_key(|(name, _)| *name);
        if rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("Duplicate Tranco domain.".into());
        }
        let data_len: usize = rows.iter().map(|(name, _)| name.len()).sum();
        if data_len > MAX_LIST {
            return Err("Tranco domain data exceeds 32 MiB.".into());
        }
        let mut data = String::with_capacity(data_len);
        let mut offsets = Vec::with_capacity(rows.len() + 1);
        let mut ranks = Vec::with_capacity(rows.len());
        for (name, rank) in rows {
            offsets.push(data.len() as u32);
            data.push_str(name);
            ranks.push(rank);
        }
        offsets.push(data.len() as u32);
        Ok(Self {
            source_entries: source_entries as u32,
            domains: List {
                modified: source_date.into(),
                data,
                offsets,
            },
            ranks,
            list_id: list_id.into(),
            downloaded,
        })
    }
    pub fn lookup(&self, hostname: &str) -> Option<(&str, u32)> {
        let mut suffix = hostname;
        loop {
            if let Some(index) = self.domains.index(suffix) {
                return Some((self.domains.at(index), self.ranks[index]));
            }
            suffix = suffix.split_once('.')?.1;
        }
    }
    pub fn storage_bytes(&self) -> usize {
        self.domains.storage_bytes() + self.ranks.len() * 4 + self.list_id.len()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.storage_bytes() + 40);
        out.extend_from_slice(RANK_MAGIC);
        out.extend_from_slice(&self.source_entries.to_le_bytes());
        out.extend_from_slice(&self.downloaded.to_le_bytes());
        out.extend_from_slice(&(self.list_id.len() as u32).to_le_bytes());
        out.extend_from_slice(self.list_id.as_bytes());
        self.domains.encode(&mut out);
        for rank in &self.ranks {
            out.extend_from_slice(&rank.to_le_bytes());
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read_sized(bytes, bytes.len())
    }
    pub fn read_sized(reader: impl Read, size: usize) -> Result<Self> {
        if size > MAX_RANK_CACHE {
            return Err("Tranco cache exceeds its size limit.".into());
        }
        // Rank uniqueness validation needs at most one byte per source entry.
        Self::read_bounded(reader, size + MAX_DOMAINS)
    }
    pub fn read_bounded(reader: impl Read, memory_budget: usize) -> Result<Self> {
        let mut input = Decoder::new(reader, MAX_RANK_CACHE, memory_budget);
        if &input.array::<8>()? != RANK_MAGIC {
            return Err("Unknown Tranco cache format.".into());
        }
        let source_entries = input.u32()?;
        if source_entries == 0 || source_entries as usize > MAX_DOMAINS {
            return Err("Invalid Tranco source size.".into());
        }
        let downloaded = u64::from_le_bytes(input.array()?);
        let id_len = input.u32()? as usize;
        if id_len == 0 || id_len > 32 {
            return Err("Invalid Tranco list ID.".into());
        }
        let list_id = input.string(id_len)?;
        if !list_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("Invalid Tranco list ID.".into());
        }
        let domains = List::decode(&mut input)?;
        let ranks = input.u32s(domains.len())?;
        input.finish()?;
        if ranks.len() > source_entries as usize {
            return Err("Invalid Tranco entry count.".into());
        }
        input.reserve(source_entries as usize)?;
        let mut seen = vec![false; source_entries as usize];
        for (index, &rank) in ranks.iter().enumerate() {
            if rank == 0
                || rank as usize > seen.len()
                || std::mem::replace(&mut seen[rank as usize - 1], true)
                || !domains.at(index).contains('.')
                || domains.at(index).parse::<std::net::IpAddr>().is_ok()
            {
                return Err("Invalid Tranco cache ranks or domains.".into());
            }
        }
        Ok(Self {
            source_entries,
            domains,
            ranks,
            list_id,
            downloaded,
        })
    }
}

#[cfg(test)]
mod rank_tests {
    use super::*;
    #[test]
    fn service_records_are_skipped_without_renumbering_hosts() {
        let db = Rankings::parse(
            "1,example.com\n2,_dns.resolver.arpa\n3,ws\n4,child.example.com\n",
            "TEST",
            "date",
            1,
        )
        .unwrap();
        let decoded = Rankings::decode(&db.encode()).unwrap();
        assert_eq!(decoded.source_entries, 4);
        assert_eq!(decoded.domains.len(), 2);
        assert_eq!(
            decoded.lookup("child.example.com"),
            Some(("child.example.com", 4))
        );
        assert_eq!(decoded.lookup("_dns.resolver.arpa"), None);
    }
    #[test]
    fn ranks_survive_sorting_roundtrip_and_parent_matching() {
        let rankings = Rankings::parse(
            "1,z.example\r\n2,example.com\r\n3,child.example.com\r\n",
            "TEST",
            "2026-10-15T00:00:00Z",
            1,
        )
        .unwrap();
        let decoded = Rankings::decode(&rankings.encode()).unwrap();
        assert_eq!(decoded.lookup("z.example"), Some(("z.example", 1)));
        assert_eq!(decoded.lookup("www.example.com"), Some(("example.com", 2)));
        assert_eq!(
            decoded.lookup("child.example.com"),
            Some(("child.example.com", 3))
        );
        assert_eq!(decoded.lookup("notexample.com"), None);
        assert_eq!(decoded.lookup("example.com.evil"), None);
        for csv in [
            "",
            "1,a.example\n3,b.example",
            "1,a.example\n2,A.example",
            "0,a.example",
            "1,127.0.0.1",
            "1,example",
            "1,a.example,extra",
            "1,a.example\n\n",
        ] {
            assert!(Rankings::parse(csv, "TEST", "date", 1).is_err(), "{csv}");
        }
        let bytes = rankings.encode();
        for length in 0..bytes.len() {
            assert!(Rankings::decode(&bytes[..length]).is_err());
        }
        let mut bad = bytes.clone();
        let len = bad.len();
        bad[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Rankings::decode(&bad).is_err());
        let mut duplicate = bytes.clone();
        let len = duplicate.len();
        let value = duplicate[len - 8..len - 4].to_vec();
        duplicate[len - 4..].copy_from_slice(&value);
        assert!(Rankings::decode(&duplicate).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(Rankings::decode(&extra).is_err());
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    struct ShortReads<'a>(&'a [u8]);
    impl Read for ShortReads<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let len = output.len().min(3);
            self.0.read(&mut output[..len])
        }
    }
    #[test]
    fn streaming_decode_accounts_for_final_storage_and_validation_scratch() {
        let snapshot = Snapshot {
            big: List::parse("||example.org^").unwrap(),
            nsfw: List::parse("||xxx^").unwrap(),
            downloaded: 1,
        };
        let bytes = snapshot.encode();
        let memory = snapshot.big.storage_bytes() + snapshot.nsfw.storage_bytes();
        assert_eq!(
            Snapshot::read_bounded(ShortReads(&bytes), memory)
                .unwrap()
                .encode(),
            bytes
        );
        assert!(Snapshot::read_bounded(ShortReads(&bytes), memory - 1).is_err());
        let ranks = Rankings::parse(
            "1,example.org\n2,example.net",
            "TEST",
            "2026-10-15T00:00:00Z",
            1,
        )
        .unwrap();
        let bytes = ranks.encode();
        let memory = ranks.storage_bytes() + ranks.source_entries as usize;
        assert_eq!(
            Rankings::read_bounded(ShortReads(&bytes), memory)
                .unwrap()
                .encode(),
            bytes
        );
        assert!(Rankings::read_bounded(ShortReads(&bytes), memory - 1).is_err());
        for cut in 0..bytes.len() {
            assert!(Rankings::read_bounded(ShortReads(&bytes[..cut]), memory).is_err());
        }
        // Forged lengths are rejected on budget before allocating their storage.
        let mut forged = snapshot.encode();
        forged[20..24].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(
            Snapshot::read_bounded(ShortReads(&forged), 1024)
                .err()
                .unwrap()
                .contains("memory budget")
        );
    }
}
