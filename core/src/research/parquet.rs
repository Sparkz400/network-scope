// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! A small Parquet writer for the research tables (`research export parquet`).
//!
//! No library is used: the files are uncompressed, every column is PLAIN encoded in one data
//! page (version 1) per row group, and the footer (Thrift compact protocol) is written by hand.
//! That is all the tables need: 64-bit integers, doubles and UTF-8 text, each required or
//! optional (NULL). The format is described in `parquet-format` (`README.md`, `Encodings.md`,
//! `parquet.thrift`); DuckDB, pyarrow and pandas read the output, see `docs/src/research.md` for
//! what was checked and when.
//!
//! The writer buffers one row group (at most [`ROW_GROUP_ROWS`] rows) in memory, so memory use
//! does not grow with the table. A table without rows gets a file with no row group.
use std::io::Write;

/// Rows per row group.
pub const ROW_GROUP_ROWS: usize = 50_000;

/// The physical type of a column. Text is `BYTE_ARRAY` annotated as UTF-8 (`STRING`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Int64,
    Double,
    Text,
}

impl Kind {
    /// The `Type` enum of `parquet.thrift`.
    fn physical(self) -> i32 {
        match self {
            Kind::Int64 => 2,
            Kind::Double => 5,
            Kind::Text => 6,
        }
    }
}

/// One column of the schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: Kind,
    /// An optional column carries a definition level per value (NULL is allowed).
    pub nullable: bool,
}

/// One value of a row.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Double(f64),
    Text(String),
}

// ---- Thrift compact protocol (only what the file metadata needs) ------------------------------

const T_I32: u8 = 5;
const T_I64: u8 = 6;
const T_BINARY: u8 = 8;
const T_LIST: u8 = 9;
const T_STRUCT: u8 = 12;

/// An encoder for one Thrift struct; fields must be written in ascending id order.
struct Compact {
    out: Vec<u8>,
    last: Vec<i16>,
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

impl Compact {
    fn new() -> Self {
        Compact {
            out: vec![],
            last: vec![0],
        }
    }

    fn header(&mut self, id: i16, kind: u8) {
        let last = self.last.last_mut().expect("inside a struct");
        let delta = id - *last;
        if (1..=15).contains(&delta) {
            self.out.push((delta as u8) << 4 | kind);
        } else {
            self.out.push(kind);
            varint(&mut self.out, zigzag(i64::from(id)));
        }
        *last = id;
    }

    fn i32(&mut self, id: i16, v: i32) {
        self.header(id, T_I32);
        varint(&mut self.out, zigzag(i64::from(v)));
    }

    fn i64(&mut self, id: i16, v: i64) {
        self.header(id, T_I64);
        varint(&mut self.out, zigzag(v));
    }

    fn string(&mut self, id: i16, v: &str) {
        self.header(id, T_BINARY);
        self.binary_body(v);
    }

    fn binary_body(&mut self, v: &str) {
        varint(&mut self.out, v.len() as u64);
        self.out.extend_from_slice(v.as_bytes());
    }

    fn list_header(&mut self, id: i16, elem: u8, len: usize) {
        self.header(id, T_LIST);
        if len < 15 {
            self.out.push((len as u8) << 4 | elem);
        } else {
            self.out.push(0xf0 | elem);
            varint(&mut self.out, len as u64);
        }
    }

    fn i32_list(&mut self, id: i16, values: &[i32]) {
        self.list_header(id, T_I32, values.len());
        for v in values {
            varint(&mut self.out, zigzag(i64::from(*v)));
        }
    }

    fn string_list(&mut self, id: i16, values: &[&str]) {
        self.list_header(id, T_BINARY, values.len());
        for v in values {
            self.binary_body(v);
        }
    }

    /// Starts a struct field (`id`), or a list element when `id` is `None`.
    fn begin(&mut self, id: Option<i16>) {
        if let Some(id) = id {
            self.header(id, T_STRUCT);
        }
        self.last.push(0);
    }

    fn end(&mut self) {
        self.out.push(0);
        self.last.pop();
    }
}

/// `SchemaElement` of the root (`schema`, with the number of columns).
fn root_element(c: &mut Compact, columns: usize) {
    c.begin(None);
    c.string(4, "schema");
    c.i32(5, columns as i32);
    c.end();
}

fn column_element(c: &mut Compact, col: &Column) {
    c.begin(None);
    c.i32(1, col.kind.physical());
    c.i32(3, if col.nullable { 1 } else { 0 });
    c.string(4, &col.name);
    if col.kind == Kind::Text {
        c.i32(6, 0); // ConvertedType UTF8
        c.begin(Some(10)); // LogicalType union: field 1 = STRING (an empty struct)
        c.begin(Some(1));
        c.end();
        c.end();
    }
    c.end();
}

// ---- The writer -------------------------------------------------------------------------------

/// What the footer remembers about one written column chunk.
struct ChunkInfo {
    offset: i64,
    total: i64,
    values: i64,
}

struct RowGroupInfo {
    chunks: Vec<ChunkInfo>,
    rows: i64,
    bytes: i64,
}

/// Writes one table. Call [`Writer::row`] per row and [`Writer::finish`] at the end.
pub struct Writer<W: Write> {
    out: W,
    position: i64,
    columns: Vec<Column>,
    pending: Vec<Vec<Cell>>,
    groups: Vec<RowGroupInfo>,
    rows: i64,
}

const MAGIC: &[u8; 4] = b"PAR1";

impl<W: Write> Writer<W> {
    pub fn new(mut out: W, columns: Vec<Column>) -> std::io::Result<Self> {
        out.write_all(MAGIC)?;
        Ok(Writer {
            out,
            position: 4,
            pending: vec![vec![]; columns.len()],
            columns,
            groups: vec![],
            rows: 0,
        })
    }

    /// Adds one row. The cells must match the schema: `Null` only in nullable columns, `Int` in
    /// `Int64`, `Double` in `Double` and `Text` in `Text` columns.
    pub fn row(&mut self, cells: Vec<Cell>) -> Result<(), String> {
        if cells.len() != self.columns.len() {
            return Err(format!(
                "a row has {} cells, the schema {} columns",
                cells.len(),
                self.columns.len()
            ));
        }
        for (cell, col) in cells.iter().zip(&self.columns) {
            let fits = matches!(
                (cell, col.kind),
                (Cell::Int(_), Kind::Int64)
                    | (Cell::Double(_), Kind::Double)
                    | (Cell::Text(_), Kind::Text)
            ) || (matches!(cell, Cell::Null) && col.nullable);
            if !fits {
                return Err(format!("column {}: {cell:?} does not fit", col.name));
            }
        }
        for (slot, cell) in self.pending.iter_mut().zip(cells) {
            slot.push(cell);
        }
        if self.pending[0].len() >= ROW_GROUP_ROWS {
            self.flush_group().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.out.write_all(bytes)?;
        self.position += bytes.len() as i64;
        Ok(())
    }

    fn flush_group(&mut self) -> std::io::Result<()> {
        let rows = self.pending.first().map_or(0, Vec::len);
        if rows == 0 {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        self.pending = vec![vec![]; self.columns.len()];
        let mut info = RowGroupInfo {
            chunks: vec![],
            rows: rows as i64,
            bytes: 0,
        };
        for (col, cells) in self.columns.clone().iter().zip(pending) {
            let page = encode_page(col, &cells);
            let offset = self.position;
            // PageHeader: type DATA_PAGE (0), sizes, DataPageHeader{num_values, PLAIN, RLE, RLE}
            let mut h = Compact::new();
            h.i32(1, 0);
            h.i32(2, page.len() as i32);
            h.i32(3, page.len() as i32);
            h.begin(Some(5));
            h.i32(1, rows as i32);
            h.i32(2, 0);
            h.i32(3, 3);
            h.i32(4, 3);
            h.end();
            h.out.push(0);
            self.write(&h.out)?;
            self.write(&page)?;
            let total = self.position - offset;
            info.bytes += total;
            info.chunks.push(ChunkInfo {
                offset,
                total,
                values: rows as i64,
            });
        }
        self.rows += rows as i64;
        self.groups.push(info);
        Ok(())
    }

    /// Flushes the last row group and writes the footer. Returns the underlying writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        self.flush_group()?;
        let mut m = Compact::new();
        m.i32(1, 1); // version
        m.list_header(2, T_STRUCT, self.columns.len() + 1);
        root_element(&mut m, self.columns.len());
        for col in &self.columns {
            column_element(&mut m, col);
        }
        m.i64(3, self.rows);
        m.list_header(4, T_STRUCT, self.groups.len());
        for g in &self.groups {
            m.begin(None);
            m.list_header(1, T_STRUCT, g.chunks.len());
            for (chunk, col) in g.chunks.iter().zip(&self.columns) {
                m.begin(None); // ColumnChunk
                m.i64(2, chunk.offset);
                m.begin(Some(3)); // ColumnMetaData
                m.i32(1, col.kind.physical());
                m.i32_list(2, if col.nullable { &[0, 3] } else { &[0] });
                m.string_list(3, &[&col.name]);
                m.i32(4, 0); // UNCOMPRESSED
                m.i64(5, chunk.values);
                m.i64(6, chunk.total);
                m.i64(7, chunk.total);
                m.i64(9, chunk.offset);
                m.end();
                m.end();
            }
            m.i64(2, g.bytes);
            m.i64(3, g.rows);
            m.end();
        }
        // no version: the same table gives the same bytes in every release (and the fixture test holds)
        m.string(6, "network-scope");
        m.out.push(0);
        let footer = std::mem::take(&mut m.out);
        self.write(&footer)?;
        self.write(&(footer.len() as u32).to_le_bytes())?;
        self.write(MAGIC)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// The page body: definition levels (optional columns) then the PLAIN values of the non-null
/// cells.
fn encode_page(col: &Column, cells: &[Cell]) -> Vec<u8> {
    let mut body = vec![];
    if col.nullable {
        // RLE/bit-packed hybrid with bit width 1: one bit-packed run covering every value, the
        // last group padded with zeros; preceded by its length (4 bytes, little endian).
        let groups = cells.len().div_ceil(8);
        let mut levels = vec![];
        varint(&mut levels, (groups as u64) << 1 | 1);
        let mut bits = vec![0u8; groups];
        for (i, c) in cells.iter().enumerate() {
            if !matches!(c, Cell::Null) {
                bits[i / 8] |= 1 << (i % 8);
            }
        }
        levels.extend_from_slice(&bits);
        body.extend_from_slice(&(levels.len() as u32).to_le_bytes());
        body.extend_from_slice(&levels);
    }
    for c in cells {
        match c {
            Cell::Null => {}
            Cell::Int(v) => body.extend_from_slice(&v.to_le_bytes()),
            Cell::Double(v) => body.extend_from_slice(&v.to_le_bytes()),
            Cell::Text(s) => {
                body.extend_from_slice(&(s.len() as u32).to_le_bytes());
                body.extend_from_slice(s.as_bytes());
            }
        }
    }
    body
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // ---- a minimal reader of what the writer produces (the structure check) ----------------

    /// A decoded Thrift value; only what the tests look at.
    #[derive(Clone, Debug, PartialEq)]
    enum T {
        Int(i64),
        Bin(Vec<u8>),
        List(Vec<T>),
        Struct(Vec<(i16, T)>),
    }

    impl T {
        fn field(&self, id: i16) -> &T {
            match self {
                T::Struct(f) => {
                    &f.iter()
                        .find(|(i, _)| *i == id)
                        .unwrap_or_else(|| panic!("no field {id} in {self:?}"))
                        .1
                }
                other => panic!("not a struct: {other:?}"),
            }
        }
        fn has(&self, id: i16) -> bool {
            matches!(self, T::Struct(f) if f.iter().any(|(i, _)| *i == id))
        }
        fn int(&self) -> i64 {
            match self {
                T::Int(v) => *v,
                other => panic!("not an int: {other:?}"),
            }
        }
        fn text(&self) -> String {
            match self {
                T::Bin(b) => String::from_utf8(b.clone()).unwrap(),
                other => panic!("not binary: {other:?}"),
            }
        }
        fn list(&self) -> &[T] {
            match self {
                T::List(l) => l,
                other => panic!("not a list: {other:?}"),
            }
        }
    }

    struct Reader<'a> {
        b: &'a [u8],
        at: usize,
    }

    impl Reader<'_> {
        fn byte(&mut self) -> u8 {
            self.at += 1;
            self.b[self.at - 1]
        }
        fn varint(&mut self) -> u64 {
            let (mut v, mut shift) = (0u64, 0);
            loop {
                let b = self.byte();
                v |= u64::from(b & 0x7f) << shift;
                if b < 0x80 {
                    return v;
                }
                shift += 7;
            }
        }
        fn zigzag(&mut self) -> i64 {
            let v = self.varint();
            (v >> 1) as i64 ^ -((v & 1) as i64)
        }
        fn value(&mut self, kind: u8) -> T {
            match kind {
                5 | 6 => T::Int(self.zigzag()),
                8 => {
                    let n = self.varint() as usize;
                    self.at += n;
                    T::Bin(self.b[self.at - n..self.at].to_vec())
                }
                9 => {
                    let h = self.byte();
                    let n = if h >> 4 == 15 {
                        self.varint() as usize
                    } else {
                        (h >> 4) as usize
                    };
                    T::List((0..n).map(|_| self.value(h & 15)).collect())
                }
                12 => self.structure(),
                other => panic!("unexpected Thrift type {other}"),
            }
        }
        fn structure(&mut self) -> T {
            let (mut fields, mut last) = (vec![], 0i16);
            loop {
                let h = self.byte();
                if h == 0 {
                    return T::Struct(fields);
                }
                let id = if h >> 4 == 0 {
                    self.zigzag() as i16
                } else {
                    last + (h >> 4) as i16
                };
                last = id;
                let v = self.value(h & 15);
                fields.push((id, v));
            }
        }
    }

    /// The metadata and every column of a file written by this module, decoded again.
    fn read_file(bytes: &[u8]) -> (T, Vec<Vec<Cell>>) {
        assert_eq!(&bytes[..4], b"PAR1");
        assert_eq!(&bytes[bytes.len() - 4..], b"PAR1");
        let n = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap())
            as usize;
        let footer = &bytes[bytes.len() - 8 - n..bytes.len() - 8];
        let mut r = Reader { b: footer, at: 0 };
        let meta = r.structure();
        assert_eq!(r.at, footer.len(), "the footer is exactly one struct");
        let schema = meta.field(2).list();
        let leaves = &schema[1..];
        let mut columns: Vec<Vec<Cell>> = vec![vec![]; leaves.len()];
        for g in meta.field(4).list() {
            let rows = g.field(3).int() as usize;
            for (i, chunk) in g.field(1).list().iter().enumerate() {
                let md = chunk.field(3);
                assert_eq!(chunk.field(2).int(), md.field(9).int());
                let start = md.field(9).int() as usize;
                let mut pr = Reader {
                    b: bytes,
                    at: start,
                };
                let header = pr.structure();
                let size = header.field(3).int() as usize;
                assert_eq!(header.field(2).int() as usize, size);
                assert_eq!(pr.at - start + size, md.field(7).int() as usize);
                let dph = header.field(5);
                assert_eq!(dph.field(1).int() as usize, rows);
                assert_eq!(dph.field(2).int(), 0, "PLAIN");
                let page = &bytes[pr.at..pr.at + size];
                let leaf = &leaves[i];
                let kind = leaf.field(1).int();
                let optional = leaf.field(3).int() == 1;
                let mut at = 0;
                let mut present = vec![true; rows];
                if optional {
                    let n = u32::from_le_bytes(page[..4].try_into().unwrap()) as usize;
                    let levels = &page[4..4 + n];
                    at = 4 + n;
                    let mut lr = Reader { b: levels, at: 0 };
                    let h = lr.varint();
                    assert_eq!(h & 1, 1, "a bit-packed run");
                    assert_eq!(h >> 1, rows.div_ceil(8) as u64);
                    for (r, p) in present.iter_mut().enumerate() {
                        *p = levels[lr.at + r / 8] >> (r % 8) & 1 == 1;
                    }
                    assert_eq!(lr.at + (h >> 1) as usize, levels.len());
                }
                for p in present {
                    if !p {
                        columns[i].push(Cell::Null);
                        continue;
                    }
                    match kind {
                        2 => {
                            columns[i].push(Cell::Int(i64::from_le_bytes(
                                page[at..at + 8].try_into().unwrap(),
                            )));
                            at += 8;
                        }
                        5 => {
                            columns[i].push(Cell::Double(f64::from_le_bytes(
                                page[at..at + 8].try_into().unwrap(),
                            )));
                            at += 8;
                        }
                        6 => {
                            let n =
                                u32::from_le_bytes(page[at..at + 4].try_into().unwrap()) as usize;
                            columns[i].push(Cell::Text(
                                String::from_utf8(page[at + 4..at + 4 + n].to_vec()).unwrap(),
                            ));
                            at += 4 + n;
                        }
                        other => panic!("type {other}"),
                    }
                }
                assert_eq!(at, page.len(), "the page holds exactly its values");
            }
        }
        (meta, columns)
    }

    /// The cell values of every column of a file this module wrote (for the tests of the
    /// exporter, which compare them with the NDJSON export).
    pub(crate) fn columns_of(bytes: &[u8]) -> Vec<Vec<Cell>> {
        read_file(bytes).1
    }

    fn schema() -> Vec<Column> {
        let c = |name: &str, kind, nullable| Column {
            name: name.into(),
            kind,
            nullable,
        };
        vec![
            c("id", Kind::Int64, false),
            c("ttl", Kind::Int64, true),
            c("score", Kind::Double, true),
            c("ip", Kind::Text, false),
            c("note", Kind::Text, true),
        ]
    }

    fn sample(n: usize) -> Vec<Vec<Cell>> {
        (0..n)
            .map(|i| {
                vec![
                    Cell::Int(i as i64 - 3),
                    if i % 3 == 0 {
                        Cell::Null
                    } else {
                        Cell::Int(i64::MAX - i as i64)
                    },
                    if i % 4 == 1 {
                        Cell::Double(i as f64 / 7.0)
                    } else {
                        Cell::Null
                    },
                    Cell::Text(format!("10.0.{}.{}", i / 256, i % 256)),
                    if i % 5 == 0 {
                        Cell::Text("ü ' \" \n 日本".into())
                    } else {
                        Cell::Null
                    },
                ]
            })
            .collect()
    }

    fn write(rows: &[Vec<Cell>]) -> Vec<u8> {
        let mut w = Writer::new(vec![], schema()).unwrap();
        for r in rows {
            w.row(r.clone()).unwrap();
        }
        w.finish().unwrap()
    }

    #[test]
    fn compact_integers_use_zigzag_varints() {
        let mut v = vec![];
        varint(&mut v, zigzag(-1));
        varint(&mut v, zigzag(300));
        varint(&mut v, zigzag(i64::MIN));
        assert_eq!(v[0], 1);
        assert_eq!(&v[1..3], &[0xd8, 0x04]); // 600
        assert_eq!(
            &v[3..],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn the_structure_round_trips() {
        let rows = sample(21);
        let bytes = write(&rows);
        let (meta, columns) = read_file(&bytes);
        assert_eq!(meta.field(3).int(), 21);
        let schema_elements = meta.field(2).list();
        assert_eq!(schema_elements.len(), 6);
        assert_eq!(schema_elements[0].field(4).text(), "schema");
        assert_eq!(schema_elements[0].field(5).int(), 5);
        assert_eq!(schema_elements[4].field(4).text(), "ip");
        assert_eq!(
            schema_elements[4].field(6).int(),
            0,
            "text is annotated UTF8"
        );
        assert!(!schema_elements[1].has(6), "integers are not annotated");
        assert_eq!(schema_elements[1].field(3).int(), 0, "id is required");
        assert_eq!(schema_elements[2].field(3).int(), 1, "ttl is optional");
        assert_eq!(meta.field(6).text(), "network-scope");
        assert_eq!(meta.field(4).list().len(), 1, "one row group");
        for (i, col) in columns.iter().enumerate() {
            let want: Vec<Cell> = rows.iter().map(|r| r[i].clone()).collect();
            assert_eq!(col, &want, "column {i}");
        }
    }

    #[test]
    fn large_tables_split_into_row_groups() {
        let rows = sample(ROW_GROUP_ROWS * 2 + 17);
        let bytes = write(&rows);
        let (meta, columns) = read_file(&bytes);
        assert_eq!(meta.field(3).int() as usize, rows.len());
        let groups = meta.field(4).list();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[2].field(3).int(), 17);
        assert_eq!(columns[3].len(), rows.len());
        assert_eq!(columns[3][ROW_GROUP_ROWS], rows[ROW_GROUP_ROWS][3]);
        assert_eq!(columns[1].last(), rows.last().map(|r| &r[1]));
    }

    #[test]
    fn an_empty_table_is_a_valid_file_without_row_groups() {
        let bytes = write(&[]);
        let (meta, columns) = read_file(&bytes);
        assert_eq!(meta.field(3).int(), 0);
        assert!(meta.field(4).list().is_empty());
        assert!(columns.iter().all(Vec::is_empty));
        assert_eq!(meta.field(2).list().len(), 6, "the schema is still there");
    }

    #[test]
    fn cells_that_do_not_fit_the_schema_are_refused() {
        let mut w = Writer::new(vec![], schema()).unwrap();
        let mut row = sample(1).remove(0);
        row[0] = Cell::Null; // `id` is required
        assert!(w.row(row).unwrap_err().contains("id"));
        let mut row = sample(1).remove(0);
        row[3] = Cell::Int(1);
        assert!(w.row(row).is_err());
        assert!(w.row(vec![Cell::Int(1)]).is_err(), "wrong width");
        assert!(w.row(sample(1).remove(0)).is_ok());
    }

    #[test]
    fn the_output_is_deterministic() {
        assert_eq!(write(&sample(9)), write(&sample(9)));
    }

    const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/research/sample.parquet");

    #[test]
    fn the_fixture_file_is_what_the_writer_produces() {
        // `tests/fixtures/research/sample.parquet` was read back with pyarrow and DuckDB (see
        // docs/src/research.md); this keeps the bytes from drifting. Regenerate it with
        // `NS_WRITE_FIXTURES=1 cargo test -p network-scope-core the_fixture_file`.
        let bytes = write(&sample(21));
        if std::env::var_os("NS_WRITE_FIXTURES").is_some() {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../tests/fixtures/research/sample.parquet"
            );
            std::fs::write(path, &bytes).unwrap();
        }
        assert_eq!(
            bytes, FIXTURE,
            "regenerate the fixture if the change is on purpose"
        );
        let (_, columns) = read_file(FIXTURE);
        assert_eq!(columns[0][0], Cell::Int(-3));
    }
}
