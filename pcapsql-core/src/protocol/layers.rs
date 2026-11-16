//! Where the fields of a packet's layers are kept, and how they are read.
//!
//! A parser does not return its fields: it writes them through a
//! [`FieldSink`] into storage that belongs to the caller, and returns a small
//! [`Parsed`]. The storage is a [`ParseBuf`], kept from packet to packet: one
//! vector for the fields of every layer of the packet, one for the layers
//! (each a range of the field vector), and an arena for the values a parser
//! has to construct (a decompressed DNS name, the list of TCP SACK edges).
//! [`ParseBuf::for_packet`] lends all three out for one packet as a
//! [`PacketLayers`]; a consumer reads a layer through a [`LayerRef`].
//!
//! Field values are `Copy` and borrow either the packet or the arena, so
//! forgetting one packet's layers is two length stores and a pointer reset:
//! no destructor runs, and once the storage has grown to what the packets
//! need, parsing allocates nothing.

use std::fmt::{self, Write as _};

use bumpalo::Bump;

use super::{FieldEntry, FieldSet, FieldValue, HintKey, Hints, ParseContext, Protocol, TunnelType};
use crate::format::names::Name;

/// Where a parser puts the fields of the layer it parses.
///
/// [`push`](Self::push) appends a field. A value that exists in the packet
/// is borrowed from it (`FieldValue::Str`, `FieldValue::Bytes`); one that has
/// to be constructed is put in the packet's arena with [`str`](Self::str),
/// [`format`](Self::format), [`name`](Self::name), [`list`](Self::list), a
/// [`ListBuilder`] or a
/// [`TextBuilder`], and lives as long as the packet's layers do.
pub struct FieldSink<'s, 'a> {
    fields: &'s mut Vec<FieldEntry<'a>>,
    /// The index in `fields` of the layer's first field.
    start: usize,
    bump: &'a Bump,
}

impl<'a> FieldSink<'_, 'a> {
    /// Append a field of the layer.
    #[inline]
    pub fn push(&mut self, field: FieldEntry<'a>) {
        self.fields.push(field);
    }

    /// The fields written to the layer so far.
    #[inline]
    pub fn as_slice(&self) -> &[FieldEntry<'a>] {
        &self.fields[self.start..]
    }

    /// `text`, copied into the arena.
    #[inline]
    pub fn text(&self, text: &str) -> &'a str {
        self.bump.alloc_str(text)
    }

    /// Formatted text, written straight into the arena: no intermediate
    /// `String`.
    pub fn text_fmt(&self, args: fmt::Arguments<'_>) -> &'a str {
        if let Some(text) = args.as_str() {
            return text;
        }
        let mut text = bumpalo::collections::String::new_in(self.bump);
        // Writing to an arena string does not fail; a `Display` impl that
        // reports an error of its own leaves what it wrote before.
        let _ = text.write_fmt(args);
        text.into_bump_str()
    }

    /// A string value, copied into the arena.
    #[inline]
    pub fn str(&self, text: &str) -> FieldValue<'a> {
        FieldValue::Str(self.text(text))
    }

    /// A string value formatted into the arena:
    /// `fields.format(format_args!("{major}.{minor}"))`.
    #[inline]
    pub fn format(&self, args: fmt::Arguments<'_>) -> FieldValue<'a> {
        FieldValue::Str(self.text_fmt(args))
    }

    /// The text of a name table ([`format::names`](crate::format::names))
    /// as a string value: the table's own string for a number with a name,
    /// text written into the arena for one without.
    #[inline]
    pub fn name(&self, name: Name) -> FieldValue<'a> {
        match name.as_static() {
            Some(text) => FieldValue::Str(text),
            None => self.format(format_args!("{name}")),
        }
    }

    /// A string value assembled piece by piece in the arena.
    #[inline]
    pub fn text_builder(&self) -> TextBuilder<'a> {
        TextBuilder {
            text: bumpalo::collections::String::new_in(self.bump),
        }
    }

    /// A list value, built in the arena from items whose number is known.
    #[inline]
    pub fn list<I>(&self, items: I) -> FieldValue<'a>
    where
        I: IntoIterator<Item = FieldValue<'a>>,
        I::IntoIter: ExactSizeIterator,
    {
        FieldValue::List(self.bump.alloc_slice_fill_iter(items))
    }

    /// A list value that grows in the arena, for items whose number is not
    /// known beforehand.
    #[inline]
    pub fn list_builder(&self) -> ListBuilder<'a> {
        ListBuilder {
            items: bumpalo::collections::Vec::new_in(self.bump),
        }
    }
}

/// A list value under construction in a packet's arena
/// ([`FieldSink::list_builder`]).
pub struct ListBuilder<'a> {
    items: bumpalo::collections::Vec<'a, FieldValue<'a>>,
}

impl<'a> ListBuilder<'a> {
    /// Append an item.
    #[inline]
    pub fn push(&mut self, item: FieldValue<'a>) {
        self.items.push(item);
    }

    /// The list.
    #[inline]
    pub fn finish(self) -> FieldValue<'a> {
        FieldValue::List(self.items.into_bump_slice())
    }
}

/// A string under construction in a packet's arena
/// ([`FieldSink::text_builder`]). It is a [`fmt::Write`], so `write!` appends
/// to it.
pub struct TextBuilder<'a> {
    text: bumpalo::collections::String<'a>,
}

impl<'a> TextBuilder<'a> {
    /// Append `text`.
    #[inline]
    pub fn push_str(&mut self, text: &str) {
        self.text.push_str(text);
    }

    /// Whether nothing was appended yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The text, as a string value.
    #[inline]
    pub fn finish(self) -> FieldValue<'a> {
        FieldValue::Str(self.text.into_bump_str())
    }
}

impl fmt::Write for TextBuilder<'_> {
    #[inline]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.text.push_str(text);
        Ok(())
    }
}

/// How a parser's attempt at a layer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status<'a> {
    /// The layer was parsed; the walk goes on with the next one.
    Ok,
    /// The parser extracted some fields and then failed. The layer is kept
    /// with those fields (when it has any) and the walk stops.
    Partial(&'a str),
    /// These bytes are not a layer of this protocol. The fields the parser
    /// wrote are discarded and the walk stops.
    Error(&'a str),
}

/// What a parser returns: the bytes it left, the hints for the layer that
/// follows, and how the parse ended. The fields are where the parser wrote
/// them, in its [`FieldSink`].
#[derive(Debug, Clone, Copy)]
pub struct Parsed<'a> {
    /// The unparsed bytes: the payload of the layer.
    pub remaining: &'a [u8],
    /// Hints for the parser of the next layer.
    pub child_hints: Hints,
    /// How the parse ended.
    pub status: Status<'a>,
}

impl<'a> Parsed<'a> {
    /// The layer was parsed.
    #[inline]
    pub fn ok(remaining: &'a [u8], child_hints: Hints) -> Self {
        Self {
            remaining,
            child_hints,
            status: Status::Ok,
        }
    }

    /// The parser failed after extracting fields, which are kept.
    #[inline]
    pub fn partial(remaining: &'a [u8], error: &'a str) -> Self {
        Self {
            remaining,
            child_hints: Hints::new(),
            status: Status::Partial(error),
        }
    }

    /// The bytes are not a layer of this protocol.
    #[inline]
    pub fn error(error: &'a str, remaining: &'a [u8]) -> Self {
        Self {
            remaining,
            child_hints: Hints::new(),
            status: Status::Error(error),
        }
    }

    /// A child hint by key.
    #[inline]
    pub fn hint(&self, key: HintKey) -> Option<u64> {
        self.child_hints.get(key)
    }

    /// Whether the parse ended without an error.
    #[inline]
    pub fn is_ok(&self) -> bool {
        self.status == Status::Ok
    }
}

/// One layer of a packet: its parser, where its fields are in the packet's
/// field vector, and the tunnel it was found in.
#[derive(Debug, Clone, Copy)]
struct Layer<'a> {
    name: &'static str,
    /// The layer's fields: a range of [`PacketLayers::fields`].
    start: u32,
    end: u32,
    encap_depth: u8,
    tunnel_type: TunnelType,
    tunnel_id: Option<u64>,
    /// The bytes the parser left.
    payload: &'a [u8],
    error: Option<&'a str>,
}

/// Storage for the layers of one packet at a time, kept from packet to
/// packet so that parsing allocates for the first packets only.
///
/// A layer's values borrow the packet they were parsed from and every packet
/// has a lifetime of its own, so the storage cannot be vectors of fields and
/// layers: their type would name one packet's lifetime. Between packets the
/// buffer keeps the allocations as empty vectors of `'static` elements;
/// [`for_packet`](Self::for_packet) lends them out as empty vectors of the
/// lifetime the caller needs, and the guard puts them back, emptied, when it
/// is dropped.
///
/// ```
/// use pcapsql_core::protocol::{default_registry, parse_packet, ParseBuf, ParseScope};
///
/// let registry = default_registry();
/// let scope = ParseScope::full();
/// let mut buf = ParseBuf::new();
/// for packet in [vec![0xffu8; 14], vec![0x00u8; 60]] {
///     let layers = parse_packet(&registry, 1, &packet, &scope, &mut buf);
///     for layer in layers.iter() {
///         println!("{}: {} fields", layer.name(), layer.fields().len());
///     }
/// }
/// ```
#[derive(Debug, Default)]
pub struct ParseBuf {
    /// Always empty: only its capacity matters.
    fields: Vec<FieldEntry<'static>>,
    /// Always empty: only its capacity matters.
    layers: Vec<Layer<'static>>,
    /// The values the last packet's parsers constructed. Reset for the next
    /// packet; the memory stays.
    bump: Bump,
}

impl ParseBuf {
    /// A buffer without storage yet: the first packets with layers allocate.
    pub fn new() -> Self {
        Self::default()
    }

    /// The capacity of the field and of the layer storage.
    #[cfg(test)]
    pub(super) fn capacity(&self) -> (usize, usize) {
        (self.fields.capacity(), self.layers.capacity())
    }

    /// The buffer's storage as the (empty) layers of one packet. It returns
    /// to the buffer when the guard is dropped.
    ///
    /// `'a` is the lifetime of the layers' values: no longer than the packet
    /// lives and no longer than this borrow of the buffer, whose arena they
    /// may point into. Taking the buffer by `&mut` is what makes resetting
    /// the arena sound: no value of an earlier packet can still be borrowed.
    #[inline]
    pub fn for_packet<'buf, 'a>(&'buf mut self) -> PacketLayers<'buf, 'a>
    where
        'buf: 'a,
    {
        self.bump.reset();
        let fields = recycle(std::mem::take(&mut self.fields));
        let layers = recycle(std::mem::take(&mut self.layers));
        PacketLayers {
            spare_fields: &mut self.fields,
            spare_layers: &mut self.layers,
            fields,
            layers,
            bump: &self.bump,
        }
    }
}

/// `items` emptied, as a vector of another element type, in the same
/// allocation. Only ever used between two instantiations of one type that
/// differ in a lifetime.
///
/// There is no `unsafe` here. Collecting a `vec::IntoIter` into a `Vec` of
/// elements with the same size and alignment reuses the source's allocation
/// (the standard library's in-place collection). The iterator is empty, so no
/// element is ever converted: the closure only gives the result its type. A
/// standard library that did not collect in place would leave this correct
/// and make it allocate once per packet, which `tests/parse_alloc.rs` counts
/// and would fail on.
#[inline(always)]
fn recycle<T, U>(mut items: Vec<T>) -> Vec<U> {
    // Nothing to keep: a scan that parses nothing (`frames` alone) never
    // gives the buffer storage, and does not pay for the conversion below.
    if items.capacity() == 0 {
        return Vec::new();
    }
    items.clear();
    items
        .into_iter()
        .map(|_| -> U { unreachable!("the vector was cleared before it was recycled") })
        .collect()
}

/// The layers of one packet, in storage borrowed from a [`ParseBuf`].
///
/// [`parse_packet`](super::parse_packet) fills it; [`iter`](Self::iter) and
/// [`get`](Self::get) read the layers, outermost first.
#[derive(Debug)]
pub struct PacketLayers<'buf, 'a> {
    spare_fields: &'buf mut Vec<FieldEntry<'static>>,
    spare_layers: &'buf mut Vec<Layer<'static>>,
    /// The fields of every layer, in layer order.
    fields: Vec<FieldEntry<'a>>,
    layers: Vec<Layer<'a>>,
    bump: &'a Bump,
}

impl Drop for PacketLayers<'_, '_> {
    #[inline]
    fn drop(&mut self) {
        *self.spare_fields = recycle(std::mem::take(&mut self.fields));
        *self.spare_layers = recycle(std::mem::take(&mut self.layers));
    }
}

impl<'a> PacketLayers<'_, 'a> {
    /// The number of layers.
    #[inline]
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Whether the packet has no layer (nothing was parsed).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Where the field and the layer storage are.
    #[cfg(test)]
    pub(super) fn storage(&self) -> (usize, usize) {
        (self.fields.as_ptr().addr(), self.layers.as_ptr().addr())
    }

    #[inline]
    fn layer_ref<'l>(&'l self, layer: &Layer<'a>) -> LayerRef<'l, 'a> {
        LayerRef {
            name: layer.name,
            fields: &self.fields[layer.start as usize..layer.end as usize],
            encap_depth: layer.encap_depth,
            tunnel_type: layer.tunnel_type,
            tunnel_id: layer.tunnel_id,
            payload: layer.payload,
            error: layer.error,
        }
    }

    /// The layer at `index`, counting from the outermost.
    #[inline]
    pub fn get(&self, index: usize) -> Option<LayerRef<'_, 'a>> {
        self.layers.get(index).map(|layer| self.layer_ref(layer))
    }

    /// The innermost layer.
    #[inline]
    pub fn last(&self) -> Option<LayerRef<'_, 'a>> {
        self.layers.last().map(|layer| self.layer_ref(layer))
    }

    /// The first (outermost) layer parsed by the parser called `name`.
    pub fn find(&self, name: &str) -> Option<LayerRef<'_, 'a>> {
        self.iter().find(|layer| layer.name() == name)
    }

    /// The layers, outermost first.
    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = LayerRef<'_, 'a>> + DoubleEndedIterator {
        self.layers.iter().map(|layer| self.layer_ref(layer))
    }

    /// The parsers' names, outermost first.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &'static str> + '_ {
        self.layers.iter().map(|layer| layer.name)
    }

    /// Run `parser` on `data` and append the layer it parses.
    ///
    /// The parser writes its fields behind those of the layers before it.
    /// The layer is recorded with the tunnel that `context` is in. A parse
    /// that ends in [`Status::Error`] leaves no layer and no field; one that
    /// ends in [`Status::Partial`] leaves a layer if it wrote a field.
    /// `projection` limits the fields a parser that supports it extracts
    /// ([`Protocol::parse_projected`]); `None` extracts all.
    #[inline]
    pub fn parse_layer<P: Protocol + ?Sized>(
        &mut self,
        parser: &P,
        data: &'a [u8],
        context: &ParseContext,
        projection: Option<FieldSet>,
    ) -> Parsed<'a> {
        let start = self.fields.len();
        let mut sink = FieldSink {
            fields: &mut self.fields,
            start,
            bump: self.bump,
        };
        let parsed = match projection {
            None => parser.parse(data, context, &mut sink),
            Some(projection) => parser.parse_projected(data, context, projection, &mut sink),
        };
        debug_assert!(
            projection.is_none_or(|projection| {
                let names = parser.field_names();
                names.is_empty()
                    || self.fields[start..].iter().all(|(name, _)| {
                        names
                            .iter()
                            .position(|n| n == name)
                            .is_some_and(|position| projection.contains(position))
                    })
            }),
            "{} wrote a field outside its projection {projection:?}: {:?}",
            parser.name(),
            &self.fields[start..]
        );
        let error = match parsed.status {
            Status::Ok => None,
            Status::Partial(error) if self.fields.len() > start => Some(error),
            Status::Partial(_) | Status::Error(_) => {
                self.fields.truncate(start);
                return parsed;
            }
        };
        self.layers.push(Layer {
            name: parser.name(),
            start: start as u32,
            end: self.fields.len() as u32,
            encap_depth: context.encap_depth,
            tunnel_type: context.current_tunnel_type(),
            tunnel_id: context.current_tunnel_id(),
            payload: parsed.remaining,
            error,
        });
        parsed
    }

    /// Append a copy of `layer`: a layer that was not parsed here (one built
    /// with [`LayerRef::new`], or a layer of another packet's storage).
    pub fn push_layer(&mut self, layer: LayerRef<'_, 'a>) {
        let start = self.fields.len() as u32;
        self.fields.extend_from_slice(layer.fields);
        self.layers.push(Layer {
            name: layer.name,
            start,
            end: self.fields.len() as u32,
            encap_depth: layer.encap_depth,
            tunnel_type: layer.tunnel_type,
            tunnel_id: layer.tunnel_id,
            payload: layer.payload,
            error: layer.error,
        });
    }
}

/// Where [`LayerRef::get_hinted`] last found a field.
///
/// Starts empty (no position matches, the first lookup scans). One per
/// column of a table, kept across rows.
#[derive(Debug, Clone, Copy)]
pub struct FieldHint {
    position: usize,
    key: &'static str,
}

impl Default for FieldHint {
    fn default() -> Self {
        Self {
            position: usize::MAX,
            key: "",
        }
    }
}

/// One layer of a packet: the parser that produced it, its fields, and the
/// tunnel it was found in. A view of fields that are kept elsewhere, in a
/// [`PacketLayers`] as a rule.
#[derive(Debug, Clone, Copy)]
pub struct LayerRef<'l, 'a> {
    name: &'static str,
    fields: &'l [FieldEntry<'a>],
    encap_depth: u8,
    tunnel_type: TunnelType,
    tunnel_id: Option<u64>,
    payload: &'a [u8],
    error: Option<&'a str>,
}

impl<'l, 'a> LayerRef<'l, 'a> {
    /// `fields` as a layer of the parser called `name`, outside any tunnel:
    /// a layer that no parser produced, for whoever reads layers to be given
    /// some (a test, a producer of its own).
    pub fn new(name: &'static str, fields: &'l [FieldEntry<'a>]) -> Self {
        Self {
            name,
            fields,
            encap_depth: 0,
            tunnel_type: TunnelType::None,
            tunnel_id: None,
            payload: &[],
            error: None,
        }
    }

    /// The layer, as found at tunnel depth `encap_depth` in a tunnel of
    /// `tunnel_type` with identifier `tunnel_id`.
    pub fn in_tunnel(
        mut self,
        encap_depth: u8,
        tunnel_type: TunnelType,
        tunnel_id: Option<u64>,
    ) -> Self {
        self.encap_depth = encap_depth;
        self.tunnel_type = tunnel_type;
        self.tunnel_id = tunnel_id;
        self
    }

    /// The name of the parser that produced the layer (`"tcp"`).
    #[inline]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The layer's fields, in the order the parser wrote them.
    #[inline]
    pub fn fields(&self) -> &'l [FieldEntry<'a>] {
        self.fields
    }

    /// Encapsulation depth of the layer (0: not inside a tunnel).
    #[inline]
    pub fn encap_depth(&self) -> u8 {
        self.encap_depth
    }

    /// The type of the innermost tunnel around the layer.
    #[inline]
    pub fn tunnel_type(&self) -> TunnelType {
        self.tunnel_type
    }

    /// The identifier of the innermost tunnel around the layer (VNI, GRE
    /// key, TEID), if it has one.
    #[inline]
    pub fn tunnel_id(&self) -> Option<u64> {
        self.tunnel_id
    }

    /// The bytes the layer's parser left: the layer's payload, which the
    /// next layer (if any) was parsed from.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The error of a layer whose parser failed after extracting the fields
    /// the layer has ([`Status::Partial`]).
    #[inline]
    pub fn error(&self) -> Option<&'a str> {
        self.error
    }

    /// A field's value by name (a linear search; a layer has few fields).
    #[inline]
    pub fn get(&self, name: &str) -> Option<&'l FieldValue<'a>> {
        self.fields.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// [`get`](Self::get) with a guess at where the field is.
    ///
    /// A parser emits its fields in a fixed order, so a column's field is
    /// almost always where it was in the previous row. `hint` remembers that
    /// position and the parser's own `&'static str` for the name: when the
    /// entry there is the same string (same pointer and length) it is the
    /// answer, in one compare; otherwise the lookup scans as `get` does and
    /// moves the hint to what it found.
    ///
    /// The hint only ever stores a position found by that scan, i.e. a first
    /// occurrence of the name. A hit at that position is the same answer as
    /// `get` unless a row repeats a key *and* its first occurrence moved to
    /// where a later one sat in the previous row. The parsers that repeat a
    /// key (TLS, one `handshake_type` per message of a record) emit it after
    /// a fixed prefix, so the first occurrence does not move; debug builds
    /// check every hit against `get`.
    #[inline]
    pub fn get_hinted(&self, name: &str, hint: &mut FieldHint) -> Option<&'l FieldValue<'a>> {
        if let Some((key, value)) = self.fields.get(hint.position) {
            if std::ptr::eq(key.as_ptr(), hint.key.as_ptr()) && key.len() == hint.key.len() {
                debug_assert!(
                    self.get(name).is_some_and(|v| std::ptr::eq(v, value)),
                    "hinted lookup of {name} disagrees with get"
                );
                return Some(value);
            }
        }
        let position = self.fields.iter().position(|(k, _)| *k == name)?;
        let (key, value) = &self.fields[position];
        *hint = FieldHint { position, key };
        Some(value)
    }
}
