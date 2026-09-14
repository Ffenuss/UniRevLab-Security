"""Standard IL2CPP metadata + ELF64 offline workflow, no target code execution.

Layouts: https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Il2Cpp/MetadataClass.cs
and Il2CppClass.cs. Supports standard metadata 27, 29, 31 and AArch64 ELF.
Original synthetic demo reader remains separate; it is not used here.
"""
from __future__ import annotations
import bisect
import collections
import copy
import hashlib
import json
import math
import mmap
import os
from pathlib import Path
import struct
import zipfile
from modkit.arch.arm64 import mov_imm, ret


class Cancelled(Exception):
    pass


def check(cb=None, stage=None):
    if cb is not None:
        if cb.isCancelled():
            raise Cancelled('Операция отменена')
        if stage:
            cb.progress(stage)


def digest(path, cb=None):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(1024 * 1024):
            check(cb)
            h.update(chunk)
    return h.hexdigest()


class Binary:
    def __init__(self, path):
        self.f = open(path, 'rb')
        try:
            self.b = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            self.f.close()
            raise ValueError('Файл пуст или недоступен')

    def close(self):
        self.b.close()
        self.f.close()

    def unpack(self, fmt, off):
        size = struct.calcsize(fmt)
        if off < 0 or off + size > len(self.b):
            raise ValueError('Повреждённый файл: выход за границы таблицы')
        return struct.unpack_from(fmt, self.b, off)


class Metadata(Binary):
    def __init__(self, path):
        super().__init__(path)
        try:
            magic, self.version = self.unpack('<II', 0)
            if magic != 0xFAB11BAF:
                raise ValueError('Нет стандартного заголовка IL2CPP. Файл повреждён, зашифрован или имеет иной формат.')
            if self.version not in (27, 29, 31):
                raise ValueError(f'Метаданные v{self.version}: автоматический разбор этой версии пока не реализован. Поддержаны v27, v29, v31.')
            self.strings = self.region(2)
            self.types = self.region(19, 88)
            self.methods = self.region(5, 36 if self.version == 31 else 32)
            # Il2CppParameterDefinition is 12 bytes for supported metadata
            # versions 27/29/31: nameIndex, token, typeIndex.
            self.parameters = self.region(10, 12)
            # Il2CppFieldDefinition: nameIndex, typeIndex, token.
            self.fields = self.region(11, 12)
            # Standard post-24.x IL2CPP metadata tables used by dev25 virtual dispatch proof.
            # 16 = interfaces (TypeIndex), 17 = vtableMethods (EncodedMethodIndex),
            # 18 = interfaceOffsets (TypeIndex, vtable offset).  Empty tables are valid.
            self.interfaces = self.region(16, 4)
            self.vtable_methods = self.region(17, 4)
            self.interface_offsets = self.region(18, 8)
            self.images = self.region(20, 40)
            if not self.types[1] or not self.images[1]:
                raise ValueError('В метаданных отсутствуют таблицы типов или сборок')
            self.type_count = self.types[1] // 88
            self.method_size = 36 if self.version == 31 else 32
            self.method_count = self.methods[1] // self.method_size
            self.parameter_count = self.parameters[1] // 12
            self.field_count = self.fields[1] // 12
            self.vtable_method_count = self.vtable_methods[1] // 4
            self.interface_offset_count = self.interface_offsets[1] // 8
        except Exception:
            self.close()
            raise

    def region(self, index, stride=1):
        off, size = self.unpack('<II', 8 + index * 8)
        if off + size > len(self.b) or size % stride or (size and off < 176):
            raise ValueError('Некорректные границы/размер таблицы метаданных')
        return off, size

    def string(self, i):
        start, size = self.strings
        if i >= size:
            raise ValueError('Индекс строки вне таблицы метаданных')
        end = self.b.find(b'\0', start + i, start + size)
        if end < 0:
            raise ValueError('Строка метаданных не завершена')
        return self.b[start + i:end].decode('utf-8', 'strict')

    def iter_rows(self, cb=None):
        """Stream method rows without materializing the entire metadata table.

        Large IL2CPP metadata commonly contains 150k+ methods.  Most correlation
        passes only need a few counters or selected rows, so keeping every row as
        a Python dict needlessly inflates RSS.  The validation rules are identical
        to :meth:`rows`; callers which require a stable list can still use rows().
        """
        occupied = set()
        for pos in range(self.images[0], sum(self.images), 40):
            check(cb)
            ni, _, first, count = self.unpack('<IiII', pos)
            if count == 0:
                continue
            if first + count > self.type_count:
                raise ValueError('Диапазон типов сборки повреждён')
            image = self.string(ni)
            for ti in range(first, first + count):
                if ti % 256 == 0:
                    check(cb)
                if ti in occupied:
                    raise ValueError('Пересекающиеся диапазоны типов')
                occupied.add(ti)
                tp = self.types[0] + ti * 88
                name, namespace = self.unpack('<II', tp)
                generic = self.unpack('<i', tp + 24)[0]
                method_start = self.unpack('<i', tp + 36)[0]
                method_count = self.unpack('<H', tp + 64)[0]
                if method_count and (method_start < 0 or method_start + method_count > self.method_count):
                    raise ValueError('Диапазон методов повреждён')
                cls = '.'.join(filter(None, (self.string(namespace), self.string(name))))
                for mi in range(method_start, method_start + method_count):
                    if mi % 1024 == 0:
                        check(cb)
                    mp = self.methods[0] + mi * self.method_size
                    mni, declaring, rt = self.unpack('<Iii', mp)
                    shift = 4 if self.version == 31 else 0
                    parameter_start = self.unpack('<i', mp + 12 + shift)[0]
                    mg = self.unpack('<i', mp + 16 + shift)[0]
                    token, flags, iflags, slot, argc = self.unpack('<IHHHH', mp + 20 + shift)
                    if declaring != ti or token >> 24 != 6:
                        raise ValueError('Токен или владелец метода не соответствует таблице')
                    if argc and (parameter_start < 0 or parameter_start + argc > self.parameter_count):
                        raise ValueError('Диапазон параметров метода повреждён')
                    yield dict(id=mi, image=image, cls=cls, name=self.string(mni),
                               declaring_type_index=ti,
                               type_index=rt, token=token, args=argc, flags=flags,
                               parameter_start=parameter_start, slot=slot,
                               is_static=bool(flags & 0x10), virtual=bool(flags & 0x40),
                               generic=generic >= 0 or mg >= 0, abstract=bool(flags & 0x400))

    def rows(self, cb=None):
        return list(self.iter_rows(cb))

    def type_definition(self, type_index):
        """Return the bounded post-24.5 Il2CppTypeDefinition fields used by dev25.

        Metadata versions 27/29/31 share the 88-byte layout consumed elsewhere in
        this reader.  We intentionally expose only indices/counts needed for
        receiver/vtable/interface proof and reject every out-of-range table slice.
        """
        ti = int(type_index)
        if not 0 <= ti < self.type_count:
            raise ValueError('Индекс TypeDefinition вне таблицы')
        tp = self.types[0] + ti * 88
        name, namespace, byval, declaring, parent, element, generic, flags = self.unpack('<IIiiii iI'.replace(' ', ''), tp)
        field_start, method_start, event_start, property_start, nested_start, interfaces_start, vtable_start, interface_offsets_start = self.unpack('<8i', tp + 32)
        method_count, property_count, field_count, event_count, nested_count, vtable_count, interfaces_count, interface_offsets_count = self.unpack('<8H', tp + 64)
        bitfield, token = self.unpack('<II', tp + 80)
        return {
            'typeDefIndex': ti, 'name': self.string(name), 'namespace': self.string(namespace),
            'label': '.'.join(filter(None, (self.string(namespace), self.string(name)))),
            'byvalTypeIndex': byval, 'declaringTypeIndex': declaring, 'parentTypeIndex': parent,
            'elementTypeIndex': element, 'genericContainerIndex': generic, 'flags': flags,
            'fieldStart': field_start, 'methodStart': method_start, 'eventStart': event_start,
            'propertyStart': property_start, 'nestedTypesStart': nested_start,
            'interfacesStart': interfaces_start, 'vtableStart': vtable_start,
            'interfaceOffsetsStart': interface_offsets_start, 'methodCount': method_count,
            'propertyCount': property_count, 'fieldCount': field_count, 'eventCount': event_count,
            'nestedTypeCount': nested_count, 'vtableCount': vtable_count,
            'interfacesCount': interfaces_count, 'interfaceOffsetsCount': interface_offsets_count,
            'bitfield': bitfield, 'token': token, 'isInterface': bool(flags & 0x20),
        }

    def method_definition(self, method_index):
        mi = int(method_index)
        if not 0 <= mi < self.method_count:
            raise ValueError('Индекс MethodDefinition вне таблицы')
        mp = self.methods[0] + mi * self.method_size
        name, declaring, return_type = self.unpack('<Iii', mp)
        shift = 4 if self.version == 31 else 0
        parameter_start = self.unpack('<i', mp + 12 + shift)[0]
        generic = self.unpack('<i', mp + 16 + shift)[0]
        token, flags, iflags, slot, argc = self.unpack('<IHHHH', mp + 20 + shift)
        return {
            'metadataMethodId': mi, 'name': self.string(name), 'declaringTypeIndex': declaring,
            'returnTypeIndex': return_type, 'parameterStart': parameter_start,
            'genericContainerIndex': generic, 'token': token, 'flags': flags, 'iflags': iflags,
            'slot': slot, 'parameterCount': argc, 'isStatic': bool(flags & 0x10),
            'isVirtual': bool(flags & 0x40), 'isAbstract': bool(flags & 0x400),
        }

    @staticmethod
    def decode_encoded_method_index(encoded, version=29):
        value = int(encoded) & 0xFFFFFFFF
        usage = (value & 0xE0000000) >> 29
        decoded = ((value & 0x1FFFFFFE) >> 1) if int(version) >= 27 else (value & 0x1FFFFFFF)
        return usage, decoded

    def vtable_entries_for_type(self, type_index):
        """Resolve MethodDef-backed metadata vtable entries for one concrete type.

        Encoded MethodRef/generic entries deliberately remain unresolved here;
        promoting those requires MethodSpec/GenericMethod proof from CodeRegistration.
        """
        td = self.type_definition(type_index)
        start, count = int(td['vtableStart']), int(td['vtableCount'])
        if count == 0:
            return []
        if start < 0 or start + count > self.vtable_method_count:
            raise ValueError('Диапазон vtableMethods повреждён')
        out = []
        for i in range(count):
            encoded = self.unpack('<I', self.vtable_methods[0] + (start + i) * 4)[0]
            usage, decoded = self.decode_encoded_method_index(encoded, self.version)
            item = {'vtableIndex': start + i, 'encoded': encoded, 'usage': usage,
                    'decodedIndex': decoded, 'methodDefResolved': False}
            if usage == 3 and 0 <= decoded < self.method_count:
                md = self.method_definition(decoded)
                if int(md['slot']) != 0xFFFF:
                    item.update({'methodDefResolved': True, 'metadataMethodId': decoded,
                                 'metadataSlot': int(md['slot']), 'method': md})
            elif usage == 6:
                item['blocker'] = 'generic-methodref-requires-methodspec-proof'
            else:
                item['blocker'] = 'unsupported-encoded-vtable-usage'
            out.append(item)
        return out

    def interface_offsets_for_type(self, type_index):
        td = self.type_definition(type_index)
        start, count = int(td['interfaceOffsetsStart']), int(td['interfaceOffsetsCount'])
        if count == 0:
            return []
        if start < 0 or start + count > self.interface_offset_count:
            raise ValueError('Диапазон interfaceOffsets повреждён')
        out = []
        for i in range(count):
            type_index_value, offset = self.unpack('<ii', self.interface_offsets[0] + (start + i) * 8)
            out.append({'entryIndex': start + i, 'interfaceTypeIndex': type_index_value,
                        'vtableOffset': offset})
        return out

    def type_owners(self, cb=None):
        """Return TypeDefinitionIndex -> (image, full class) without method rows."""
        out = {}
        occupied = set()
        for pos in range(self.images[0], sum(self.images), 40):
            check(cb)
            ni, _, first, count = self.unpack('<IiII', pos)
            if count == 0:
                continue
            if first + count > self.type_count:
                raise ValueError('Диапазон типов сборки повреждён')
            image = self.string(ni)
            for ti in range(first, first + count):
                if ti in occupied:
                    raise ValueError('Пересекающиеся диапазоны типов')
                occupied.add(ti)
                tp = self.types[0] + ti * 88
                name, namespace = self.unpack('<II', tp)
                cls = '.'.join(filter(None, (self.string(namespace), self.string(name))))
                out[ti] = (image, cls)
        return out

    def field_definition(self, field_index):
        fi = int(field_index)
        if not 0 <= fi < self.field_count:
            raise ValueError('Индекс FieldDefinition вне таблицы')
        fp = self.fields[0] + fi * 12
        name, type_index, token = self.unpack('<IiI', fp)
        return {
            'fieldDefinitionIndex': fi, 'name': self.string(name),
            'typeIndex': type_index, 'token': token,
        }

    def fields_for_type(self, type_index):
        """Return exact FieldDefinition rows owned by one TypeDefinition.

        Runtime offsets are intentionally not guessed here. They are correlated
        separately with MetadataRegistration.fieldOffsets in the ELF.
        """
        td = self.type_definition(type_index)
        start, count = int(td['fieldStart']), int(td['fieldCount'])
        if count == 0:
            return []
        if start < 0 or start + count > self.field_count:
            raise ValueError('Диапазон FieldDefinition повреждён')
        return [self.field_definition(start + i) for i in range(count)]

    def parameter_type_indices(self):
        """Yield TypeIndex values without allocating per-parameter dictionaries."""
        for pi in range(self.parameter_count):
            yield self.unpack('<i', self.parameters[0] + pi * 12 + 8)[0]

    def parameters_for(self, start, count):
        """Materialize parameter records only for a selected method."""
        if count == 0:
            return []
        if start < 0 or start + count > self.parameter_count:
            raise ValueError('Диапазон параметров метода повреждён')
        out = []
        for pi in range(start, start + count):
            pp = self.parameters[0] + pi * 12
            p_name, p_token, p_type = self.unpack('<IIi', pp)
            out.append(dict(index=pi, name=self.string(p_name), token=p_token, type_index=p_type))
        return out


class Elf(Binary):
    def __init__(self, path, cb=None):
        super().__init__(path)
        self.cb = cb
        try:
            if self.b[:6] != b'\x7fELF\x02\x01' or self.unpack('<H', 18)[0] != 183:
                raise ValueError('Нужна ELF-библиотека ARM64 (arm64-v8a), little-endian')
            if self.unpack('<H', 16)[0] != 3:
                raise ValueError('Ожидается shared library ET_DYN')
            phoff = self.unpack('<Q', 32)[0]
            entsize, count = self.unpack('<HH', 54)
            if entsize < 56 or phoff + entsize * count > len(self.b):
                raise ValueError('Таблица сегментов ELF повреждена')
            self.segments = []
            dynamic = None
            for i in range(count):
                kind, flags, off, va, _, size, mem, _ = self.unpack('<IIQQQQQQ', phoff + i * entsize)
                if off + size > len(self.b) or size > mem:
                    raise ValueError('Сегмент ELF выходит за границы файла')
                if kind == 1:
                    self.segments.append((va, off, size, flags))
                if kind == 2:
                    dynamic = (off, size)
            self.reloc = {}
            tags = {}
            if dynamic:
                for p in range(dynamic[0], sum(dynamic), 16):
                    tag, val = self.unpack('<qQ', p)
                    if tag == 0:
                        break
                    tags[tag] = val
            if 0x60000011 in tags:  # Android APS2 packed relocation format
                raise ValueError('ELF содержит упакованные Android-релокации APS2: этот формат пока не поддержан')
            if 7 in tags:
                size = tags.get(8, 0)
                stride = tags.get(9, 24)
                if stride != 24 or size % 24:
                    raise ValueError('Некорректная таблица RELA')
                base = self.offset(tags[7], size)
                for i, p in enumerate(range(base, base + size, 24)):
                    if i % 16384 == 0:
                        check(cb)
                    address, info, addend = self.unpack('<QQq', p)
                    if info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE, base=0
                        self.add_reloc(address, addend)
            # Standard DT_RELR and Android's earlier RELR tag numbers.
            relr = tags.get(36, tags.get(0x6fffe000))
            if relr is not None:
                size = tags.get(35, tags.get(0x6fffe001, 0))
                if size % 8:
                    raise ValueError('Некорректная таблица RELR')
                start = self.offset(relr, size)
                cursor = 0
                for i, p in enumerate(range(start, start + size, 8)):
                    if i % 16384 == 0:
                        check(cb)
                    word = self.unpack('<Q', p)[0]
                    if not word & 1:
                        cursor = word
                        self.add_reloc(cursor, self.unpack('<Q', self.offset(cursor, 8))[0])
                        cursor += 8
                    else:
                        for bit in range(1, 64):
                            if word & (1 << bit):
                                addr = cursor + (bit - 1) * 8
                                self.add_reloc(addr, self.unpack('<Q', self.offset(addr, 8))[0])
                        cursor += 63 * 8
        except Exception:
            self.close()
            raise

    def close(self):
        # dev16: large IL2CPP binaries can create hundreds of thousands of
        # relocation/reference entries.  Drop those Python containers before
        # unmapping the file so a subsequent APK scan does not retain their RSS.
        try:
            if hasattr(self, 'reloc'):
                self.reloc.clear()
            if hasattr(self, 'segments'):
                self.segments.clear()
        finally:
            try:
                super().close()
            except (AttributeError, ValueError):
                pass

    def add_reloc(self, address, value):
        try:
            off = self.offset(address, 8)
        except ValueError:
            return  # zero-filled tail of a load segment has no on-disk bytes
        self.reloc[off] = value

    def offset(self, va, length=1, executable=False):
        for v, off, size, flags in self.segments:
            if v <= va and va + length <= v + size and (not executable or flags & 1):
                return off + va - v
        raise ValueError('Адрес не принадлежит нужному файловому сегменту ELF')

    def virtual(self, off):
        for v, o, size, _ in self.segments:
            if o <= off < o + size:
                return v + off - o
        raise ValueError('Нет виртуального адреса для смещения')

    def ptr(self, off):
        return self.reloc.get(off, self.unpack('<Q', off)[0])

    def finds(self, pattern):
        pos = 0
        while True:
            check(self.cb)
            pos = self.b.find(pattern, pos)
            if pos < 0:
                return
            yield pos
            pos += 1

    def modules(self, image_names):
        """Resolve Il2CppCodeGenModule method tables with one ELF string pass.

        Older builds called ``finds`` once per managed image and again once per
        discovered string VA, turning a 100+ assembly title into hundreds of
        full 100-MB scans. Dev27 scans all image strings together and builds the
        relocation reverse index once. Exact pointer-byte search is a fallback
        only for names with no relocation reference.
        """
        import re
        names = sorted(set(image_names))
        if not names:
            return {}
        name_vas = collections.defaultdict(list)
        wanted_vas = set()
        patterns = [re.escape(name.encode('utf-8') + b'\0') for name in names]
        matcher = re.compile(b'|'.join(patterns))
        raw = memoryview(self.b)
        try:
            for i, hit in enumerate(matcher.finditer(raw)):
                if i % 4096 == 0:
                    check(self.cb)
                try:
                    va = self.virtual(hit.start())
                except ValueError:
                    continue
                value = bytes(hit.group(0)[:-1]).decode('utf-8', 'strict')
                name_vas[value].append(va)
                wanted_vas.add(va)
        finally:
            raw.release()

        reloc_refs = collections.defaultdict(list)
        if wanted_vas:
            for i, (off, value) in enumerate(self.reloc.items()):
                if i % 65536 == 0:
                    check(self.cb)
                if value in wanted_vas:
                    reloc_refs[value].append(off)

        out = {}
        for n, name in enumerate(names):
            check(self.cb, f'Поиск таблиц методов: {n + 1}/{len(names)} — {name}')
            candidates = set()
            for va in name_vas.get(name, []):
                refs = set(reloc_refs.get(va, []))
                # Non-relocated absolute pointers are uncommon in ET_DYN. Keep a
                # bounded compatibility fallback only when relocation proof is
                # absent instead of rescanning the file unconditionally.
                if not refs:
                    refs.update(p for p in self.finds(struct.pack('<Q', va)) if p % 8 == 0)
                for p in refs:
                    try:
                        count = self.unpack('<Q', p + 8)[0]
                        if not 0 < count <= 2_000_000:
                            continue
                        table = self.offset(self.ptr(p + 16), count * 8)
                        samples = [self.ptr(table + i * 8) for i in range(min(count, 64))]
                        nonzero = [a for a in samples if a]
                        if not nonzero:
                            continue
                        for a in nonzero:
                            self.offset(a, 4, True)
                        candidates.add((count, table))
                    except (ValueError, struct.error):
                        continue
            if len(candidates) == 1:
                out[name] = candidates.pop()
        return out

    def type_table(self, type_count, max_index):
        matches = set()
        for p in self.finds(struct.pack('<Q', type_count)):
            base = p - 96
            if base < 0 or base % 8:
                continue
            try:
                if self.unpack('<Q', base + 80)[0] != type_count:
                    continue
                count = self.unpack('<Q', base + 48)[0]
                if not max_index < count <= 4_000_000:
                    continue
                table = self.offset(self.ptr(base + 56), count * 8)
                self.offset(self.ptr(base + 88), type_count * 8)
                self.offset(self.ptr(base + 104), type_count * 8)
                for i in {0, max_index, count - 1}:
                    addr = self.offset(self.ptr(table + i * 8), 12)
                    bits = self.unpack('<I', addr + 8)[0]
                    if not 1 <= ((bits >> 16) & 255) <= 0x55:
                        raise ValueError('Неверный тип')
                matches.add((count, table))
            except (ValueError, struct.error):
                continue
        return matches.pop() if len(matches) == 1 else None

    def metadata_registration(self, type_count, max_type_index=0):
        """Locate one standard 64-bit Il2CppMetadataRegistration.

        The supported Unity/IL2CPP layout consists of 8-byte count/pointer
        pairs. ``typesCount/types`` live at +48/+56, while
        ``fieldOffsetsCount/fieldOffsets`` live at +80/+88. The function is
        deliberately strict: a unique structurally valid registration is
        required before field offsets are trusted.
        """
        matches = []
        for p in self.finds(struct.pack('<Q', int(type_count))):
            base = p - 80
            if base < 0 or base % 8:
                continue
            try:
                field_count = self.unpack('<Q', base + 80)[0]
                if field_count != int(type_count):
                    continue
                types_count = self.unpack('<Q', base + 48)[0]
                if not int(max_type_index) < types_count <= 4_000_000:
                    continue
                types_table = self.offset(self.ptr(base + 56), types_count * 8)
                field_offsets = self.offset(self.ptr(base + 88), int(type_count) * 8)
                sizes_count = self.unpack('<Q', base + 96)[0]
                if sizes_count != int(type_count):
                    continue
                type_sizes = self.offset(self.ptr(base + 104), int(type_count) * 8)
                # Validate a few Il2CppType entries exactly as type_table() does.
                for i in {0, int(max_type_index), int(types_count) - 1}:
                    addr = self.offset(self.ptr(types_table + i * 8), 12)
                    bits = self.unpack('<I', addr + 8)[0]
                    if not 1 <= ((bits >> 16) & 255) <= 0x55:
                        raise ValueError('Неверный тип')
                matches.append({
                    'baseOffset': base, 'typesCount': int(types_count),
                    'typesTableOffset': types_table,
                    'fieldOffsetsCount': int(field_count),
                    'fieldOffsetsTableOffset': field_offsets,
                    'typeDefinitionsSizesCount': int(sizes_count),
                    'typeDefinitionsSizesTableOffset': type_sizes,
                })
            except (ValueError, struct.error):
                continue
        # Deduplicate aliases caused by identical byte patterns/references.
        unique = {}
        for item in matches:
            unique[(item['baseOffset'], item['fieldOffsetsTableOffset'])] = item
        return next(iter(unique.values())) if len(unique) == 1 else None

    def runtime_field_offsets(self, registration, metadata, type_index):
        """Resolve FieldDefinition -> exact runtime instance offsets.

        Negative offsets (static/thread-static/sentinel) are retained as
        non-instance facts but never exposed as object memory offsets.
        """
        if not registration:
            return []
        ti = int(type_index)
        if not 0 <= ti < int(registration['fieldOffsetsCount']):
            return []
        fields = metadata.fields_for_type(ti)
        if not fields:
            return []
        table = int(registration['fieldOffsetsTableOffset'])
        try:
            arr_va = self.ptr(table + ti * 8)
            arr = self.offset(arr_va, len(fields) * 4)
        except ValueError:
            return []
        owner = metadata.type_definition(ti)
        out = []
        for i, field in enumerate(fields):
            off = self.unpack('<i', arr + i * 4)[0]
            out.append({
                **field, 'declaringTypeIndex': ti, 'declaringType': owner['label'],
                'runtimeOffset': (int(off) if off >= 0 else None),
                'runtimeOffsetRaw': int(off), 'isInstanceOffset': bool(off >= 0),
            })
        return out

    def metadata_type_shape(self, table, index):
        """Return a bounded description of one Il2CppType entry.

        The type enum is useful even when the type is not a primitive.  We retain
        only the by-ref signal needed to recognize conservative ``TryGet(out T)``
        instance resolvers; arbitrary managed layouts are never guessed.
        """
        if table is None or not 0 <= index < table[0]:
            return None
        try:
            off = self.offset(self.ptr(table[1] + index * 8), 12)
            data = self.unpack('<Q', off)[0]
            bits = self.unpack('<I', off + 8)[0]
            code = (bits >> 16) & 255
            # Unity has moved the by-ref bit across metadata/runtime revisions;
            # both positions are treated as pointer-like and therefore never as
            # direct primitive values.
            byref = bool(bits & 0x60000000)
            primitive = {1:'void', 2:'bool', 4:'int8', 5:'uint8', 6:'int16', 7:'uint16',
                         8:'int32', 9:'uint32', 10:'int64', 11:'uint64',
                         12:'float', 13:'double'}.get(code)
            # CLASS/VALUETYPE store an Il2CppMetadataTypeHandle / type-definition
            # index in the data union on the supported runtimes.  Keep it only as
            # a bounded identity hint; callers must validate it against the
            # metadata type table before using it for resolver correlation.
            type_def_index = None
            if code in (0x11, 0x12):
                candidate = data & 0xffffffff
                if candidate < 0x7fffffff:
                    type_def_index = int(candidate)
            return {'typeCode': code, 'byRef': byref, 'primitive': primitive,
                    'bits': bits, 'data': data, 'typeDefIndex': type_def_index}
        except ValueError:
            return None

    def metadata_primitive(self, table, index, *, allow_void=False):
        """Resolve a TypeIndex to the small direct-primitive ABI subset."""
        shape = self.metadata_type_shape(table, index)
        if not shape or shape['byRef']:
            return None
        kind = shape['primitive']
        if kind == 'void' and not allow_void:
            return None
        return kind

    def primitive(self, table, index):
        # Legacy constant-return patcher must not treat void as a value type.
        return self.metadata_primitive(table, index, allow_void=False)


def analyze(metadata_path, library_path, output_path, cb=None):
    check(cb, 'Проверка метаданных')
    m = Metadata(metadata_path)
    e = None
    try:
        rows = m.rows(cb)
        check(cb, 'Чтение сегментов и релокаций библиотеки')
        e = Elf(library_path, cb)
        modules = e.modules({r['image'] for r in rows})
        token_max = collections.defaultdict(int)
        token_seen = set()
        for row in rows:
            key = (row['image'], row['token'])
            if key in token_seen:
                raise ValueError('Повторяющиеся токены методов в одной сборке')
            token_seen.add(key)
            token_max[row['image']] = max(token_max[row['image']], row['token'] & 0xffffff)
        # Reject structurally mismatched assembly tables instead of silently using them.
        modules = {name: table for name, table in modules.items() if table[0] == token_max[name]}
        check(cb, 'Определение типов результатов')
        types = e.type_table(m.type_count, max((r['type_index'] for r in rows), default=0))
        address_counts = collections.Counter()
        for count, table in modules.values():
            for i in range(count):
                if i % 16384 == 0:
                    check(cb)
                addr = e.ptr(table + i * 8)
                if addr:
                    address_counts[addr] += 1
        addresses = sorted(address_counts)
        ready = []
        resolved = 0
        reasons = collections.Counter()
        for i, row in enumerate(rows):
            if i % 1024 == 0:
                check(cb)
            module = modules.get(row['image'])
            rid = row['token'] & 0xffffff
            addr = 0
            if module and 0 < rid <= module[0]:
                addr = e.ptr(module[1] + (rid - 1) * 8)
            try:
                off = e.offset(addr, 4, True) if addr else None
            except ValueError:
                off = None
            row['rva'] = addr if off is not None else None
            resolved += off is not None
            kind = e.primitive(types, row['type_index'])
            row['return_type'] = kind
            reason = None
            if off is None:
                reason = 'Нет проверенного адреса'
            elif row['generic'] or row['abstract']:
                reason = 'Обобщённый или абстрактный метод'
            elif not kind or row['args']:
                reason = 'Не числовой/булевый метод без аргументов'
            elif not row['name'].startswith(('get_', 'Get', 'Is', 'Has')):
                reason = 'Метод не распознан как получение значения'
            elif address_counts[addr] != 1:
                reason = 'Общий адрес у нескольких методов'
            else:
                ix = bisect.bisect_right(addresses, addr)
                span = addresses[ix] - addr if ix < len(addresses) else 0
                if span < 8 or addr % 4:
                    reason = 'Недостаточно данных о границе метода'
                else:
                    # Snapshot enough space for the longest supported constant stub.
                    capacity = min(span, 24)
                    try:
                        e.offset(addr, capacity, True)
                    except ValueError:
                        reason = 'Граница метода выходит за сегмент'
                    if reason is None:
                        ready.append(dict(id=row['id'], label=row['cls']+'::'+row['name'],
                                          image=row['image'], kind=kind, rva=addr, offset=off,
                                          capacity=capacity, original=e.b[off:off+capacity].hex()))
            row['unavailable_reason'] = reason
            if reason:
                reasons[reason] += 1
        check(cb, 'Контрольные суммы файлов')
        result = dict(schema=1, metadata_version=m.version, types=m.type_count,
                      methods=len(rows), resolved=resolved, modules=len(modules),
                      type_table_found=types is not None, candidates=ready, method_details=rows,
                      unavailable=dict(reasons), metadata_sha256=digest(metadata_path, cb),
                      library_sha256=digest(library_path, cb),
                      warning='Соответствие файлов проверено по структурам. Поведение изменений требует проверки в игре; это не подтверждение совместимости всех методов.')
        check(cb, f'Анализ завершён: {len(ready)} доступных методов')
        temp = str(output_path)+'.tmp'
        Path(temp).write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
        os.replace(temp, output_path)
        return json.dumps({k:v for k,v in result.items() if k != 'method_details'}, ensure_ascii=False)
    finally:
        m.close()
        if e:
            e.close()


_RODROID_TYPES = {
    'bool': 'bool', 'int8_t': 'int8', 'uint8_t': 'uint8',
    'int16_t': 'int16', 'uint16_t': 'uint16', 'int32_t': 'int32',
    'uint32_t': 'uint32', 'int64_t': 'int64', 'uint64_t': 'uint64',
    'float': 'float', 'double': 'double',
}

_SEMANTIC_WORDS = {
    'health': {'health', 'hp', 'hitpoint', 'hitpoints', 'life', 'lives', 'vitality'},
    'damage': {'damage', 'dmg', 'attack', 'hurt', 'hit', 'wound'},
    'money': {'money', 'coin', 'coins', 'gold', 'cash', 'currency', 'gem', 'gems'},
    # dev16: diagnostic/debug naming is not equivalent to an explicit cheat
    # surface.  Keeping these tags separate prevents ordinary logging APIs from
    # receiving the same priority as a concrete godmode/noclip/trainer method.
    'cheat': {'cheat', 'godmode', 'god', 'noclip', 'invincible', 'trainer'},
    'debug': {'debug', 'developer', 'console', 'devmenu'},
    'inventory': {'inventory', 'item', 'items', 'ammo', 'weapon', 'weapons'},
    'movement': {'speed', 'movespeed', 'movement', 'jump', 'stamina'},
    'state': {'state', 'mode', 'status', 'freeze', 'frozen', 'pause', 'paused'},
    'progression': {'level', 'xp', 'experience', 'unlock', 'unlocked', 'quest'},
}


def _symbol_tokens(text):
    """Split namespaces, snake_case and CamelCase without substring matches."""
    import re
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', str(text))
    return [x.lower() for x in re.findall(r'[A-Za-z][A-Za-z0-9]*', text)]


def _semantic_tags(text):
    ordered = _symbol_tokens(text)
    tokens = set(ordered)
    tokens.update(a+b for a, b in zip(ordered, ordered[1:]))
    compact = {''.join(_symbol_tokens(x)) for x in str(text).replace('::', '.').split('.')}
    return [name for name, words in _SEMANTIC_WORDS.items()
            if tokens.intersection(words) or compact.intersection(words)]


_IL2CPP_FRAMEWORK_PREFIXES = (
    'UnityEngine.', 'Unity.', 'System.', 'Microsoft.', 'Mono.', 'mscorlib', 'netstandard',
    'Android.', 'JetBrains.',
)
_IL2CPP_THIRD_PARTY_PREFIXES = (
    'Newtonsoft.', 'Google.', 'Firebase.', 'DG.Tweening', 'DOTween', 'CriWare', 'CriMana',
    'Cinemachine', 'FMOD', 'Spine', 'TMPro', 'Cysharp.', 'UniTask', 'MessagePack.',
    'BestHTTP', 'LitJson', 'protobuf', 'Google.Protobuf', 'Adjust.', 'AppsFlyer',
)

def _il2cpp_provenance(image, cls=''):
    """Classify static IL2CPP provenance for ranking, not ownership proof.

    `Assembly-CSharp` is the only strong game-primary signal.  Firstpass is kept
    separate because many projects place middleware there.  Unknown custom DLLs
    stay reviewable but do not receive the same auto-confirm weight as primary
    game code.
    """
    image = str(image or '')
    cls = str(cls or '')
    probe = image + ' ' + cls
    if image in {'Assembly-CSharp', 'Assembly-CSharp.dll'} or image.startswith('Assembly-CSharp.'):
        return 'game-primary'
    if image in {'Assembly-CSharp-firstpass', 'Assembly-CSharp-firstpass.dll'} or 'firstpass' in image.casefold():
        return 'mixed-firstpass'
    if image.startswith(_IL2CPP_FRAMEWORK_PREFIXES) or cls.startswith(_IL2CPP_FRAMEWORK_PREFIXES):
        return 'framework'
    if image.startswith(_IL2CPP_THIRD_PARTY_PREFIXES) or cls.startswith(_IL2CPP_THIRD_PARTY_PREFIXES):
        return 'third-party-known'
    low = probe.casefold()
    if any(x.casefold() in low for x in ('dotween', 'criware', 'crimana', 'cinemachine', 'fmod', 'spine', 'unitask', 'newtonsoft', 'firebase', 'google.protobuf')):
        return 'third-party-known'
    return 'custom-unknown'


def _application_il2cpp_surface(image, cls=''):
    """Backwards-compatible boolean derived from the richer provenance."""
    return _il2cpp_provenance(image, cls) in {'game-primary', 'mixed-firstpass', 'custom-unknown'}


def _rodroid_signature_contract(signature):
    # Backwards-compatible private name used by the Android engine/tests.
    from modkit.reworkspace.signature import rodroid_signature_contract
    return rodroid_signature_contract(signature)


def _dump_field_discoveries(raw_dump, start_id):
    """Extract interesting fields/properties from dump.cs as search-only evidence."""
    import re
    result, namespace, owner = [], '', ''
    class_re = re.compile(r'\b(?:class|struct)\s+([A-Za-z_$][\w$]*)')
    field_re = re.compile(r'^\s*(?:public|private|protected|internal|static|readonly|const|\s)+\s*([\w.<>,\[\]?]+)\s+([A-Za-z_$][\w$]*)\s*(?:;|\{)')
    for line in raw_dump.splitlines():
        stripped = line.strip()
        if stripped.startswith('namespace '):
            namespace = stripped[10:].strip()
        found = class_re.search(stripped)
        if found:
            owner = found.group(1)
        if re.search(r'\b(class|struct|interface|enum)\b', stripped):
            continue
        match = field_re.match(line)
        if not match or '(' in line:
            continue
        type_name, name = match.groups()
        label = '.'.join(x for x in (namespace, owner, name) if x)
        tags = _semantic_tags(label)
        if not tags:
            continue
        offset_match = re.search(r'//\s*0x([0-9A-Fa-f]+)', line)
        result.append(dict(id=start_id+len(result), label=label, image='dump.cs',
                           kind=type_name, item_type='field/property', semantic=tags,
                           field_offset=int(offset_match.group(1), 16) if offset_match else None,
                           selectable=False,
                           unavailable_reason='Поле/свойство найдено, но постоянный патч метода к нему неприменим'))
        if len(result) >= 5000:
            break
    return result




_CSHARP_PRIMITIVES = {
    'bool':'bool','sbyte':'int8','byte':'uint8','short':'int16','ushort':'uint16',
    'int':'int32','uint':'uint32','long':'int64','ulong':'uint64','float':'float','double':'double',
    'System.Boolean':'bool','System.SByte':'int8','System.Byte':'uint8','System.Int16':'int16',
    'System.UInt16':'uint16','System.Int32':'int32','System.UInt32':'uint32','System.Int64':'int64',
    'System.UInt64':'uint64','System.Single':'float','System.Double':'double',
}


def _materialize_metadata_type_shapes(meta, elf, types, type_owners, row):
    """Attach bounded return/parameter ABI shapes to one streamed metadata row.

    The function is intentionally per-row: callers may process a 100k+ method
    table without retaining parameter dictionaries after the row is serialized.
    Managed object layouts are never guessed; only primitive/by-ref/type identity
    facts exposed by MetadataRegistration are recorded.
    """
    rshape = elf.metadata_type_shape(types, row.get('type_index', -1))
    row['return_type_shape'] = rshape
    row['return_primitive'] = (None if not rshape or rshape.get('byRef') else rshape.get('primitive'))
    row['return_type_definition_index'] = rshape.get('typeDefIndex') if rshape else None
    return_owner = type_owners.get(row['return_type_definition_index'])
    if return_owner:
        row['return_type_image'], row['return_type_class'] = return_owner

    wants_params = bool(row.get('args'))
    params = meta.parameters_for(row.get('parameter_start', -1), row.get('args', 0)) if wants_params else []
    for param in params:
        shape = elf.metadata_type_shape(types, param.get('type_index', -1))
        param['type_shape'] = shape
        param['primitive'] = (None if not shape or shape.get('byRef') else shape.get('primitive'))
        param['by_ref'] = bool(shape and shape.get('byRef'))
        param['type_code'] = shape.get('typeCode') if shape else None
        param['type_definition_index'] = shape.get('typeDefIndex') if shape else None
        owner = type_owners.get(param['type_definition_index'])
        if owner:
            param['type_image'], param['type_class'] = owner
    row['parameters'] = params
    return row


def _metadata_resolution_index(metadata_path, elf, cb=None, wanted_keys=None, *, wanted_rvas=None, include_generic_retention=True, catalog_base_path=None):
    """Resolve a bounded generic/wanted subset while counting the full IL2CPP map.

    dev12-dev15 returned a 144k-entry Python dictionary for large IL2CPP titles even
    though Menu Builder only consumes semantic methods, resolver shapes and exact
    unresolved dump.cs keys.  dev16 keeps full coverage statistics and the full
    sorted unique-RVA set, but materializes metadata dictionaries only for that
    useful subset. Exact ``wanted_rvas`` may additionally force materialization
    after a name-independent native call-graph scan. This materially reduces
    Android peak RSS without weakening address uniqueness checks.  When
    ``catalog_base_path`` is supplied, the final streaming pass also emits one
    compact JSONL row for *every* metadata method.  That file is intentionally
    ABI-light and is enriched later, after the name-independent native xref scan.
    """
    import gc
    wanted_keys = set(wanted_keys or ())
    wanted_rvas = {int(x) for x in (wanted_rvas or ()) if int(x) > 0}
    meta = Metadata(metadata_path)
    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    try:
        token_max = collections.defaultdict(int)
        token_seen = set()
        max_return = 0
        for row in meta.iter_rows(cb):
            key = (row['image'], row['token'])
            if key not in token_seen:
                token_seen.add(key)
                token_max[row['image']] = max(token_max[row['image']], row['token'] & 0xffffff)
            if row.get('type_index', -1) >= 0:
                max_return = max(max_return, row['type_index'])
        modules = elf.modules(set(token_max))
        modules = {name: table for name, table in modules.items() if table[0] == token_max[name]}
        token_seen.clear()
        check(cb, 'Metadata resolver: CodeGenModule таблицы готовы')

        check(cb, 'Metadata resolver: parameter type bounds')
        max_param = max((x for x in meta.parameter_type_indices() if x >= 0), default=0)
        check(cb, 'Metadata resolver: поиск MetadataRegistration type table')
        types = elf.type_table(meta.type_count, max(max_return, max_param))
        check(cb, 'Metadata resolver: type owners')
        type_owners = meta.type_owners(cb)
        check(cb, 'Metadata resolver: type metadata готова')

        def selected(row, addr=0):
            # Every metadata row remains address-visible. This predicate controls
            # only eager typed ABI materialization. For large catalogues semantic
            # vocabulary is deferred to Evidence Graph, avoiding duplicate work.
            from modkit.reworkspace.method_evidence import should_retain_metadata_row
            wanted = ((row['image'], row['cls'], row['name'], row['args']) in wanted_keys
                      or (addr and addr in wanted_rvas))
            if wanted:
                return True
            if not include_generic_retention:
                return False
            # Dev27 large-title path: the complete address catalogue and shared
            # Evidence Graph preserve every method. Eager typed ABI materialization
            # here is therefore reserved for exact wanted rows; observed/native
            # candidates are materialized immediately after the one-pass BL scan.
            # This avoids running the retention classifier over 150k+ rows a third
            # time and keeps discovery coverage intact.
            if metadata_methods > 10000:
                return False
            semantic = _semantic_tags(row['cls'] + '::' + row['name'])
            return should_retain_metadata_row(row, semantic_tags=semantic, wanted=False)

        def raw_addr_for(row):
            module = modules.get(row['image'])
            rid = row['token'] & 0xffffff
            if not module or not 0 < rid <= module[0]:
                return 0
            return int(elf.ptr(module[1] + (rid - 1) * 8) or 0)

        def addr_for(row):
            addr = raw_addr_for(row)
            if not addr:
                return 0
            try:
                elf.offset(addr, 4, True)
            except ValueError:
                return 0
            return addr

        def key_digest(row):
            # Compact deterministic fingerprint for full-table duplicate
            # counting.  The selected subset still uses the exact tuple key.
            h = hashlib.blake2b(digest_size=8)
            h.update(str(row['image']).encode('utf-8', 'surrogatepass')); h.update(b'\0')
            h.update(str(row['cls']).encode('utf-8', 'surrogatepass')); h.update(b'\0')
            h.update(str(row['name']).encode('utf-8', 'surrogatepass')); h.update(b'\0')
            h.update(struct.pack('<I', int(row['args'])))
            return h.digest()

        check(cb, 'Metadata resolver: подсчёт уникальных RVA/ключей')
        address_counts = collections.Counter()
        full_key_counts = collections.Counter()
        metadata_methods = 0
        for i, row in enumerate(meta.iter_rows(cb)):
            if i % 4096 == 0:
                check(cb)
            metadata_methods += 1
            full_key_counts[key_digest(row)] += 1
            addr = addr_for(row)
            if addr:
                address_counts[addr] += 1

        unique_addresses = sorted(addr for addr, count in address_counts.items() if count == 1)
        check(cb, 'Metadata resolver: запись полного каталога + bounded ABI')
        index = {}
        parameter_rows_loaded = 0
        typed_high_signal = 0
        resolved_unique_methods = 0
        catalog_stats = collections.Counter()
        catalog_temp = None
        catalog_file = None
        catalog_page_file = None
        catalog_byte_offset = 0
        catalog_page_size = 30
        catalog_dense_offsets = []
        catalog_rva_pairs = []
        catalog_missing_offset = (1 << 64) - 1
        catalog_idx_temp = catalog_pages_temp = catalog_rva_temp = None
        if catalog_base_path:
            catalog_temp = str(catalog_base_path) + '.tmp'
            catalog_idx_temp = str(catalog_base_path) + '.idx.tmp'
            catalog_pages_temp = str(catalog_base_path) + '.pages.idx.tmp'
            catalog_rva_temp = str(catalog_base_path) + '.rva.idx.tmp'
            Path(catalog_temp).parent.mkdir(parents=True, exist_ok=True)
            catalog_file = open(catalog_temp, 'wb')
            catalog_page_file = open(catalog_pages_temp, 'wb')
        try:
            from modkit.reworkspace.method_evidence import method_role
            typed_budget = 4096 if metadata_methods > 10000 else metadata_methods
            for i, row in enumerate(meta.iter_rows(cb)):
                if i % 4096 == 0:
                    check(cb)
                raw_addr = raw_addr_for(row)
                addr = addr_for(row)
                key_count = full_key_counts.get(key_digest(row), 0)
                address_unique = bool(addr and address_counts.get(addr) == 1)
                if address_unique and key_count == 1:
                    resolved_unique_methods += 1

                if catalog_file is not None:
                    label = row['cls'] + '::' + row['name']
                    provenance = _il2cpp_provenance(row['image'], row['cls'])
                    module = modules.get(row['image'])
                    rid = row['token'] & 0xffffff
                    if address_unique:
                        resolution = 'confirmed-unique-code-registration'
                        reason = None
                        catalog_stats['address_confirmed'] += 1
                    elif addr:
                        resolution = 'shared-code-registration-rva'
                        reason = 'Один executable RVA связан с несколькими metadata-методами'
                        catalog_stats['shared_rva'] += 1
                    elif raw_addr:
                        resolution = 'non-executable-code-registration-pointer'
                        reason = 'CodeRegistration pointer не принадлежит исполняемому file-backed сегменту'
                        catalog_stats['non_executable_pointer'] += 1
                    elif not module:
                        resolution = 'module-table-unresolved'
                        reason = 'Таблица CodeRegistration для managed image не разрешена однозначно'
                        catalog_stats['module_unresolved'] += 1
                    elif not 0 < rid <= module[0]:
                        resolution = 'token-out-of-module-range'
                        reason = 'RID metadata token выходит за диапазон разрешённой module table'
                        catalog_stats['token_out_of_range'] += 1
                    else:
                        resolution = 'no-code-registration-pointer'
                        reason = 'Для metadata token отсутствует executable method pointer'
                        catalog_stats['no_pointer'] += 1
                    name_ambiguous = key_count != 1
                    if name_ambiguous:
                        catalog_stats['name_key_ambiguous'] += 1
                    if row.get('generic'):
                        catalog_stats['generic'] += 1
                    if row.get('abstract'):
                        catalog_stats['abstract'] += 1
                    semantic = (_semantic_tags(label) if metadata_methods <= 10000 else [])
                    catalog_contract = {}
                    # Dev27: a 150k+ catalogue is address-complete but ABI-light.
                    # Materializing every parameter/type shape here duplicates the
                    # later bounded callable window and is the dominant cost on
                    # large games. Tiny fixtures retain eager ABI for compatibility.
                    if types is not None and metadata_methods <= 10000:
                        _materialize_metadata_type_shapes(meta, elf, types, type_owners, row)
                        catalog_contract = _metadata_native_callable_contract(row, None)
                        catalog_stats['abi_materialized'] += 1
                        if catalog_contract.get('shapeSupported'):
                            catalog_stats['abi_shape_supported'] += 1
                        if catalog_contract.get('autoBindingSafe'):
                            catalog_stats['auto_binding_safe'] += 1
                    base_row = {
                        'catalog_schema': 'modkit-full-metadata-method-catalog-1.0',
                        'catalog_only': True,
                        'id': int(row['id']),
                        'metadata_method_id': int(row['id']),
                        'metadata_token': int(row['token']),
                        'return_type_index': int(row.get('type_index', -1)),
                        'parameter_start': int(row.get('parameter_start', -1)),
                        'flags': int(row.get('flags', 0)),
                        'label': label,
                        'image': row['image'],
                        'class': row['cls'],
                        'name': row['name'],
                        'declaring_type_index': int(row.get('declaring_type_index', -1)),
                        'kind': 'method',
                        'arity': int(row.get('args') or 0),
                        'metadata_slot': int(row.get('slot') or 0),
                        'is_static': bool(row.get('is_static')),
                        'generic': bool(row.get('generic')),
                        'abstract': bool(row.get('abstract')),
                        'rva': int(addr) if addr else None,
                        'raw_code_registration_rva': int(raw_addr) if raw_addr else None,
                        'resolution': resolution,
                        'address_confirmed': address_unique,
                        'name_key_ambiguous': name_ambiguous,
                        'method_role': method_role(label),
                        'semantic': semantic,
                        'provenance': provenance,
                        'application_owned': provenance in {'game-primary', 'mixed-firstpass', 'custom-unknown'},
                        'relation_status': 'not-observed',
                        'runtime_status': 'not-observed',
                        'abi_materialized': bool(catalog_contract),
                        'abi_shape_supported': bool(catalog_contract.get('shapeSupported')) if catalog_contract else False,
                        'return_type': (catalog_contract.get('metadataReturnType') if catalog_contract else None),
                        'return_type_code': (catalog_contract.get('metadataReturnTypeCode') if catalog_contract else None),
                        'return_type_definition_index': (catalog_contract.get('metadataReturnTypeDefinitionIndex') if catalog_contract else None),
                        'parameter_type_definition_indices': [
                            param.get('typeDefinitionIndex') for param in (catalog_contract.get('metadataParameters') or [])[:16]
                        ] if catalog_contract else [],
                        'parameter_type_classes': [
                            param.get('typeClass') for param in (catalog_contract.get('metadataParameters') or [])[:16]
                        ] if catalog_contract else [],
                        'parameter_types': [
                            (param.get('primitive') or param.get('typeClass') or
                             ('type#' + str(param.get('typeCode')) if param.get('typeCode') is not None else '?'))
                            for param in (catalog_contract.get('metadataParameters') or [])[:16]
                        ] if catalog_contract else [],
                        'binding_suggestion': (catalog_contract.get('bindingSuggestion') if catalog_contract else None),
                        'resolver_suggestion': (catalog_contract.get('resolverSuggestion') if catalog_contract else None),
                        'resolver_target_image': (catalog_contract.get('resolverTargetImage') if catalog_contract else None),
                        'resolver_target_class': (catalog_contract.get('resolverTargetClass') if catalog_contract else None),
                        'resolver_target_type_index': (catalog_contract.get('resolverTargetTypeDefinitionIndex') if catalog_contract else None),
                        'resolver_target_verified': bool(catalog_contract.get('resolverTargetVerified')) if catalog_contract else False,
                        'auto_binding_safe': bool(catalog_contract.get('autoBindingSafe')) if catalog_contract else False,
                        'binding_blocker': (catalog_contract.get('bindingBlocker') if catalog_contract else 'metadata-type-table-unavailable'),
                        'selectable': False,
                        'unavailable_reason': reason,
                    }
                    encoded = (json.dumps(base_row, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
                    if int(catalog_stats['rows_written']) % catalog_page_size == 0:
                        catalog_page_file.write(struct.pack('>Q', catalog_byte_offset))
                    mid = int(row['id'])
                    if mid >= len(catalog_dense_offsets):
                        catalog_dense_offsets.extend([catalog_missing_offset] * (mid + 1 - len(catalog_dense_offsets)))
                    if catalog_dense_offsets[mid] != catalog_missing_offset:
                        raise ValueError('Повторяющийся metadataMethodId в base catalog')
                    catalog_dense_offsets[mid] = catalog_byte_offset
                    if address_unique and addr:
                        catalog_rva_pairs.append((int(addr), mid))
                    catalog_file.write(encoded)
                    catalog_byte_offset += len(encoded)
                    catalog_stats['rows_written'] += 1

                if not selected(row, addr):
                    continue
                wanted_exact = ((row['image'], row['cls'], row['name'], row['args']) in wanted_keys
                                or (addr and addr in wanted_rvas))
                if len(index) >= typed_budget and not wanted_exact:
                    continue
                key = (row['image'], row['cls'], row['name'], row['args'])
                if not addr or address_counts.get(addr) != 1 or key_count != 1:
                    continue

                # If the full file-backed catalogue is enabled this row may
                # already have been typed above. Otherwise materialize it only now.
                if 'parameters' not in row or 'return_type_shape' not in row:
                    _materialize_metadata_type_shapes(meta, elf, types, type_owners, row)
                params = row.get('parameters') or []
                if params:
                    parameter_rows_loaded += 1
                if row.get('return_primitive') is not None and (row.get('args', 0) == 0 or params) and all(
                    p.get('primitive') or (p.get('by_ref') and p.get('type_code') in {0x0E, 0x12, 0x15, 0x1C, 0x1D})
                    for p in params
                ):
                    typed_high_signal += 1
                index[key] = (row, addr)
        except Exception:
            if catalog_file is not None:
                catalog_file.close(); catalog_file = None
            if catalog_page_file is not None:
                catalog_page_file.close(); catalog_page_file = None
            for tmp in (catalog_temp, catalog_idx_temp, catalog_pages_temp, catalog_rva_temp):
                if tmp:
                    try: os.unlink(tmp)
                    except FileNotFoundError: pass
            raise
        else:
            if catalog_file is not None:
                catalog_file.close(); catalog_file = None
            if catalog_page_file is not None:
                catalog_page_file.close(); catalog_page_file = None
            if catalog_base_path:
                with open(catalog_idx_temp, 'wb') as index_file:
                    for off in catalog_dense_offsets:
                        index_file.write(struct.pack('>Q', off))
                catalog_rva_pairs.sort()
                with open(catalog_rva_temp, 'wb') as rva_file:
                    for rva, mid in catalog_rva_pairs:
                        rva_file.write(struct.pack('>QI', rva, mid))
                os.replace(catalog_temp, catalog_base_path)
                os.replace(catalog_idx_temp, str(catalog_base_path)+'.idx')
                os.replace(catalog_pages_temp, str(catalog_base_path)+'.pages.idx')
                os.replace(catalog_rva_temp, str(catalog_base_path)+'.rva.idx')

        check(cb, 'Metadata resolver: завершён')
        return index, unique_addresses, dict(
            modules=len(modules), metadata_methods=metadata_methods,
            resolved_unique=resolved_unique_methods, resolved_unique_addresses=len(unique_addresses),
            type_table_found=types is not None,
            retained_index_methods=len(index), lazy_parameter_rows=parameter_rows_loaded,
            high_signal_primitive_contract_rows=typed_high_signal,
            full_catalog=dict(catalog_stats) if catalog_base_path else None,
        )
    finally:
        meta.close()
        if gc_was_enabled:
            gc.enable()


def _materialize_observed_from_base_catalog(metadata_path, elf, catalog_base_path, wanted_rvas, cb=None):
    """Materialize a bounded observed-RVA subset without rescanning CodeRegistration.

    The first metadata pass already proved unique executable RVAs and serialized
    their exact metadataMethodId into the base catalogue. Dev27 reuses that proof
    and performs only direct method-definition/type materialization for observed
    targets, avoiding a second all-method CodeRegistration pass.
    """
    wanted = {int(x) for x in (wanted_rvas or ()) if int(x) > 0}
    if not wanted or not catalog_base_path or not Path(catalog_base_path).is_file():
        return {}, {'available': True, 'selected': 0, 'strategy': 'base-catalog-direct-id'}
    selected = []
    with open(catalog_base_path, 'r', encoding='utf-8') as src:
        for n, line in enumerate(src):
            if n % 4096 == 0:
                check(cb)
            if not line.strip():
                continue
            row = json.loads(line)
            rva = row.get('rva')
            if isinstance(rva, int) and rva in wanted and row.get('address_confirmed'):
                selected.append(row)
    meta = Metadata(metadata_path)
    try:
        max_param = max((x for x in meta.parameter_type_indices() if x >= 0), default=0)
        max_return = max((int(x.get('return_type_index', -1)) for x in selected), default=0)
        types = elf.type_table(meta.type_count, max(max_param, max_return))
        owners = meta.type_owners(cb)
        out = {}
        for i, base in enumerate(selected):
            if i % 256 == 0:
                check(cb)
            mid = int(base['metadata_method_id'])
            md = meta.method_definition(mid)
            row = {
                'id': mid, 'image': base.get('image'), 'cls': base.get('class'),
                'name': base.get('name'), 'declaring_type_index': int(md['declaringTypeIndex']),
                'type_index': int(md['returnTypeIndex']), 'token': int(md['token']),
                'args': int(md['parameterCount']), 'flags': int(md['flags']),
                'parameter_start': int(md['parameterStart']), 'slot': int(md['slot']),
                'is_static': bool(md['isStatic']), 'virtual': bool(md['isVirtual']),
                'generic': bool(base.get('generic')), 'abstract': bool(base.get('abstract')),
            }
            if types is not None:
                _materialize_metadata_type_shapes(meta, elf, types, owners, row)
            key = (row['image'], row['cls'], row['name'], row['args'])
            out[key] = (row, int(base['rva']))
        return out, {
            'available': True, 'selected': len(out), 'strategy': 'base-catalog-direct-id',
            'typeTableFound': types is not None,
        }
    finally:
        meta.close()


def _arm64_direct_bl_observed_targets(elf, target_rvas, cb=None, *,
                                      max_scan_bytes=256 * 1024 * 1024,
                                      max_matches=250_000):
    """Observe direct ARM64 BL edges into *any* exact metadata method RVA.

    This is intentionally name-independent.  ``target_rvas`` is the complete set
    of unique executable CodeRegistration pointers produced by the metadata
    resolver, so an obfuscated method named ``a`` or ``xqv`` is treated exactly
    like a descriptive method name.

    The scan returns aggregate counts plus the first observed call site per target
    instead of retaining every edge.  That keeps Android heap usage bounded while
    still providing a deterministic breadth signal for later typed materialization.
    """
    import re
    wanted = {int(x) for x in (target_rvas or ()) if int(x) > 0}
    if not wanted:
        return collections.Counter(), {}, {
            'scannedBytes': 0, 'matches': 0, 'uniqueTargets': 0,
            'truncated': False, 'strategy': 'all-unique-CodeRegistration-RVAs',
        }
    high_byte = re.compile(b'[\x94-\x97]')
    counts = collections.Counter()
    first_refs = {}
    scanned = 0
    matches = 0
    truncated = False
    for va, off, size, flags in elf.segments:
        if not (flags & 1) or size < 4 or scanned >= int(max_scan_bytes):
            continue
        take = min(int(size), int(max_scan_bytes) - scanned) & ~3
        if take <= 0:
            continue
        raw = memoryview(elf.b)[off:off + take]
        try:
            for hit in high_byte.finditer(raw):
                rel = hit.start() - 3
                if rel < 0 or (rel & 3):
                    continue
                word = struct.unpack_from('<I', raw, rel)[0]
                if word & 0xFC000000 != 0x94000000:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                call_rva = int(va) + rel
                target = call_rva + (imm26 << 2)
                if target not in wanted:
                    continue
                counts[target] += 1
                matches += 1
                first_refs.setdefault(target, {
                    'callRva': call_rva,
                    'fileOffset': int(off) + rel,
                    'targetRva': target,
                    'kind': 'arm64-direct-bl',
                })
                if matches >= int(max_matches):
                    truncated = True
                    break
            if truncated:
                break
        finally:
            raw.release()
        scanned += take
        check(cb)
    return counts, first_refs, {
        'scannedBytes': scanned,
        'matches': matches,
        'uniqueTargets': len(counts),
        'truncated': truncated,
        'strategy': 'all-unique-CodeRegistration-RVAs',
    }


def _arm64_direct_bl_calls_to_target(elf, target_rva, cb=None, *,
                                       max_scan_bytes=256 * 1024 * 1024,
                                       max_matches=4096):
    """Return exact ARM64 BL call sites for one method RVA.

    Unlike the breadth scan, the deep resolver intentionally keeps the concrete
    call sites because there is only one target.  The result is still bounded and
    static-only: it proves native direct-call edges, not runtime execution.
    """
    import re
    target_rva = int(target_rva or 0)
    if target_rva <= 0:
        return [], {'scannedBytes': 0, 'matches': 0, 'truncated': False}
    high_byte = re.compile(b'[\x94-\x97]')
    refs = []
    scanned = 0
    truncated = False
    for va, off, size, flags in elf.segments:
        if not (flags & 1) or size < 4 or scanned >= int(max_scan_bytes):
            continue
        take = min(int(size), int(max_scan_bytes) - scanned) & ~3
        if take <= 0:
            continue
        raw = memoryview(elf.b)[off:off + take]
        try:
            for hit in high_byte.finditer(raw):
                rel = hit.start() - 3
                if rel < 0 or (rel & 3):
                    continue
                word = struct.unpack_from('<I', raw, rel)[0]
                if word & 0xFC000000 != 0x94000000:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                call_rva = int(va) + rel
                if call_rva + (imm26 << 2) != target_rva:
                    continue
                refs.append({
                    'callRva': call_rva, 'fileOffset': int(off) + rel,
                    'targetRva': target_rva, 'kind': 'arm64-direct-bl',
                })
                if len(refs) >= int(max_matches):
                    truncated = True
                    break
            if truncated:
                break
        finally:
            raw.release()
        scanned += take
        check(cb)
    return refs, {
        'scannedBytes': scanned, 'matches': len(refs), 'truncated': truncated,
        'strategy': 'single-exact-target-rva',
    }



def _arm64_extended_calls_to_target(elf, target_rva, metadata_slot=None, cb=None, *,
                                    max_scan_bytes=256 * 1024 * 1024,
                                    max_matches=4096):
    """Dev24 exact incoming edges: BL + BL->thunk + locally resolved BLR.

    Virtual/interface BLR shapes are returned separately as candidates.  Slot
    similarity is never treated as an exact target because static receiver type
    is not proven by the native callsite alone.
    """
    from modkit.reworkspace.arm64_flow import scan_bl_calls_via_thunk, scan_blr_calls
    direct, direct_stats = _arm64_direct_bl_calls_to_target(
        elf, target_rva, cb, max_scan_bytes=max_scan_bytes, max_matches=max_matches)
    check(cb)
    via = scan_bl_calls_via_thunk(
        elf, int(target_rva), max_scan_bytes=max_scan_bytes,
        max_matches=max(1, int(max_matches) - len(direct)))
    check(cb)
    indirect = scan_blr_calls(
        elf, target_rva=int(target_rva), target_metadata_slot=metadata_slot,
        max_scan_bytes=max_scan_bytes,
        max_matches=max_matches)
    exact = list(direct)
    exact.extend(via.get('calls') or [])
    exact.extend(indirect.get('exact') or [])
    exact.sort(key=lambda x: (int(x.get('callRva') or 0), str(x.get('kind') or '')))
    if len(exact) > int(max_matches):
        exact = exact[:int(max_matches)]
    # Exact callsites are de-duplicated by call RVA + canonical target + edge kind.
    unique = []
    seen = set()
    for row in exact:
        key = (int(row.get('callRva') or 0), int(row.get('targetRva') or 0), str(row.get('kind') or ''))
        if key in seen:
            continue
        seen.add(key); unique.append(row)
    stats = {
        # Backward-compatible aggregate fields plus dev24 per-edge counters.
        'scannedBytes': int(direct_stats.get('scannedBytes') or 0),
        'matches': len(unique),
        'exactTotal': len(unique),
        'scannedBytesDirect': int(direct_stats.get('scannedBytes') or 0),
        'directMatches': len(direct),
        'thunkMatches': len(via.get('calls') or []),
        'indirectExactMatches': len(indirect.get('exact') or []),
        'virtualCandidates': len(indirect.get('virtualCandidates') or []),
        'indirectUnresolved': len(indirect.get('unresolved') or []),
        'truncated': bool(direct_stats.get('truncated') or via.get('truncated') or indirect.get('truncated')),
        'strategy': 'direct-bl+thunk-canonicalization+local-blr-register-flow',
    }
    return unique, indirect.get('virtualCandidates') or [], stats

def _select_observed_metadata_targets(counts, *, max_rows=4096):
    """Choose a deterministic breadth-preserving subset of observed target RVAs.

    Frequency alone strongly favours framework hot paths.  When a title exposes
    more observed managed targets than the Android report budget, retain a blend
    of frequent, rare and address-spread targets.  The policy is application-
    agnostic and does not inspect method names.
    """
    items = [(int(rva), int(count)) for rva, count in (counts or {}).items()
             if int(rva) > 0 and int(count) > 0]
    cap = max(0, int(max_rows))
    if not cap or not items:
        return []
    if len(items) <= cap:
        return [rva for rva, _ in sorted(items, key=lambda x: (-x[1], x[0]))]

    frequent_n = cap // 2
    rare_n = cap // 4
    chosen = set(rva for rva, _ in sorted(items, key=lambda x: (-x[1], x[0]))[:frequent_n])
    for rva, _ in sorted(items, key=lambda x: (x[1], x[0])):
        if len(chosen) >= frequent_n + rare_n:
            break
        chosen.add(rva)

    remaining = cap - len(chosen)
    if remaining > 0:
        spread = [rva for rva, _ in sorted(items) if rva not in chosen]
        if len(spread) <= remaining:
            chosen.update(spread)
        else:
            # Evenly sample the native address space, including both ends.
            denom = max(1, remaining - 1)
            for i in range(remaining):
                ix = round(i * (len(spread) - 1) / denom) if remaining > 1 else len(spread) // 2
                chosen.add(spread[ix])
    return sorted(chosen, key=lambda rva: (-int(counts[rva]), rva))[:cap]



def _virtual_receiver_type(meta, elf, types, call, source):
    """Infer a static receiver TypeDefinition only from preserved ABI registers.

    X0 is ``this`` for an instance managed caller.  X0..X7 / X1..X7 are also
    accepted when the original register is an untouched managed parameter whose
    runtime Il2CppType resolves to one concrete CLASS TypeDefinition.  Register
    copies/locals are intentionally not guessed.
    """
    reg = call.get('receiverRegister')
    if not isinstance(reg, int) or not 0 <= reg <= 7:
        return None
    if reg == 0 and source.get('isStatic') is False:
        ti = source.get('declaringTypeIndex')
        if isinstance(ti, int) and 0 <= ti < meta.type_count:
            return {'typeDefIndex': ti, 'source': 'caller-this-x0', 'register': reg,
                    'confidence': 'exact-abi-root'}
        return None
    parameter_index = reg if source.get('isStatic') else reg - 1
    arity = int(source.get('arity') or 0)
    start = source.get('parameterStart')
    if parameter_index < 0 or parameter_index >= arity or not isinstance(start, int):
        return None
    params = meta.parameters_for(start, arity)
    if parameter_index >= len(params):
        return None
    shape = elf.metadata_type_shape(types, params[parameter_index].get('type_index', -1))
    ti = (shape or {}).get('typeDefIndex')
    if not shape or shape.get('byRef') or shape.get('typeCode') != 0x12 or not isinstance(ti, int):
        return None
    if not 0 <= ti < meta.type_count:
        return None
    return {'typeDefIndex': ti, 'source': 'managed-parameter-register', 'register': reg,
            'parameterIndex': parameter_index, 'typeShape': shape, 'confidence': 'exact-abi-root'}


def _resolve_virtual_dispatch_for_target(metadata_path, library_path, virtual_candidates,
                                         target_method_id, target_rva, cb=None):
    """Dev25 receiver-type + metadata-vtable proof for ARM64 virtual BLR.

    No Il2CppClass byte offset is hard-coded.  For each statically typed receiver
    we infer the inline ``VirtualInvokeData`` base only when the observed physical
    offsets and the receiver's complete metadata slot domain have exactly one
    common solution.  On arm64 each VirtualInvokeData entry is two pointers = 16
    bytes.  Ambiguous bases, interface-typed receivers, MethodRef entries and
    untyped register roots remain review-only.
    """
    calls = [dict(x) for x in (virtual_candidates or []) if isinstance(x.get('callRva'), int)]
    if not calls:
        return {'exactCalls': [], 'reviewCandidates': [], 'receiverGroups': [],
                'stats': {'candidates': 0, 'receiverTyped': 0, 'exact': 0}}
    caller_map = _metadata_callsite_sources(metadata_path, library_path,
                                            [x['callRva'] for x in calls], cb)
    meta = Metadata(metadata_path)
    elf = None
    try:
        elf = Elf(library_path, cb)
        source_ids = set()
        for attributed in caller_map.values():
            rows = attributed.get('sourceMethodCandidates') or []
            if len(rows) == 1 and isinstance(rows[0].get('metadataMethodId'), int):
                source_ids.add(int(rows[0]['metadataMethodId']))
        max_type_index = 0
        source_rows = {}
        if source_ids:
            for row in meta.iter_rows(cb):
                if int(row.get('id', -1)) not in source_ids:
                    continue
                source_rows[int(row['id'])] = row
                max_type_index = max(max_type_index, int(row.get('type_index') or 0))
                for param in meta.parameters_for(row.get('parameter_start', -1), row.get('args', 0)):
                    max_type_index = max(max_type_index, int(param.get('type_index') or 0))
        types = elf.type_table(meta.type_count, max_type_index)
        owners = meta.type_owners(cb)
        enriched = []
        groups = collections.defaultdict(list)
        receiver_typed = 0
        for call in calls:
            attr = caller_map.get(call['callRva']) or {}
            source_list = attr.get('sourceMethodCandidates') or []
            item = {**call, **attr}
            if len(source_list) != 1 or types is None:
                item['slotCorrelationStatus'] = 'review-no-unique-managed-caller-or-type-table'
                enriched.append(item); continue
            source = source_list[0]
            raw_source = source_rows.get(int(source.get('metadataMethodId', -1)))
            if raw_source is None:
                item['slotCorrelationStatus'] = 'review-source-metadata-row-missing'
                enriched.append(item); continue
            source = {**source,
                      'declaringTypeIndex': raw_source.get('declaring_type_index'),
                      'isStatic': bool(raw_source.get('is_static')),
                      'parameterStart': raw_source.get('parameter_start'),
                      'arity': raw_source.get('args')}
            receiver = _virtual_receiver_type(meta, elf, types, item, source)
            if not receiver:
                item['slotCorrelationStatus'] = 'review-receiver-type-not-proven'
                enriched.append(item); continue
            td = meta.type_definition(receiver['typeDefIndex'])
            receiver['label'] = owners.get(receiver['typeDefIndex'], ('', td['label']))[1] or td['label']
            receiver['isInterface'] = bool(td.get('isInterface'))
            item['receiverTypeProof'] = receiver
            if receiver['isInterface']:
                item['slotCorrelationStatus'] = 'review-interface-receiver-runtime-implementation-unknown'
                enriched.append(item); continue
            entries = [x for x in meta.vtable_entries_for_type(receiver['typeDefIndex'])
                       if x.get('methodDefResolved') and isinstance(x.get('metadataSlot'), int)]
            slot_map = collections.defaultdict(list)
            for entry in entries:
                slot_map[int(entry['metadataSlot'])].append(entry)
            valid_slots = sorted(k for k, rows in slot_map.items() if len(rows) == 1)
            physical = item.get('vtableSlotOffset')
            if not isinstance(physical, int) or physical < 0 or not valid_slots:
                item['slotCorrelationStatus'] = 'review-vtable-slot-domain-unavailable'
                enriched.append(item); continue
            item['_validSlots'] = valid_slots
            item['_slotMap'] = slot_map
            item['_typeDef'] = td
            item['slotCorrelationStatus'] = 'receiver-typed-awaiting-vtable-base-proof'
            enriched.append(item)
            groups[int(receiver['typeDefIndex'])].append(item)
            receiver_typed += 1

        exact = []
        group_reports = []
        for ti, items in groups.items():
            # Every call on the same exact receiver type must share one inline
            # VirtualInvokeData base. Intersect all mathematically valid bases.
            base_sets = []
            for item in items:
                physical = int(item['vtableSlotOffset'])
                bases = {physical - 16 * int(slot) for slot in item['_validSlots']
                         if physical - 16 * int(slot) >= 0}
                if bases:
                    base_sets.append(bases)
            common = set.intersection(*base_sets) if base_sets else set()
            td = items[0]['_typeDef']
            proof = {
                'receiverTypeIndex': ti, 'receiverType': items[0]['receiverTypeProof'].get('label'),
                'observedCallsites': len(items), 'observedPhysicalOffsets': sorted({int(x['vtableSlotOffset']) for x in items}),
                'metadataVtableCount': int(td.get('vtableCount') or 0),
                'candidateBaseOffsets': sorted(common)[:32],
                'entrySizeBytes': 16,
                'baseStatus': 'confirmed-unique-slot-domain-intersection' if len(common) == 1 else 'review-ambiguous-vtable-base',
            }
            base = next(iter(common)) if len(common) == 1 else None
            if base is not None:
                proof['vtableBaseOffset'] = int(base)
            try:
                raw_ifaces = meta.interface_offsets_for_type(ti)
                iface_rows = []
                for row in raw_ifaces:
                    shape = elf.metadata_type_shape(types, row['interfaceTypeIndex'])
                    iti = (shape or {}).get('typeDefIndex')
                    iface_rows.append({**row, 'interfaceTypeDefIndex': iti,
                                       'interfaceType': (owners.get(iti, ('', ''))[1] if isinstance(iti, int) else None)})
                proof['interfaceOffsets'] = iface_rows[:64]
            except ValueError as exc:
                proof['interfaceOffsetsError'] = str(exc)
            group_reports.append(proof)
            for item in items:
                # Strip internal helper objects before returning JSON data.
                slot_map = item.pop('_slotMap')
                item.pop('_validSlots', None); item.pop('_typeDef', None)
                if base is None:
                    item['slotCorrelationStatus'] = 'review-ambiguous-vtable-base'
                    item['vtableBaseCandidates'] = sorted(common)[:32]
                    continue
                delta = int(item['vtableSlotOffset']) - int(base)
                if delta < 0 or delta % 16:
                    item['slotCorrelationStatus'] = 'review-slot-offset-not-virtual-invoke-aligned'
                    continue
                logical_slot = delta // 16
                rows = slot_map.get(logical_slot) or []
                item['resolvedMetadataSlot'] = logical_slot
                item['vtableBaseOffset'] = int(base)
                if len(rows) != 1:
                    item['slotCorrelationStatus'] = 'review-metadata-slot-ambiguous-or-missing'
                    continue
                entry = rows[0]
                item['resolvedMetadataMethodId'] = entry.get('metadataMethodId')
                item['slotCorrelationStatus'] = ('confirmed-exact-receiver-vtable-target'
                                                if int(entry.get('metadataMethodId', -1)) == int(target_method_id)
                                                else 'confirmed-other-vtable-target')
                if int(entry.get('metadataMethodId', -1)) == int(target_method_id):
                    exact.append({**item, 'kind': 'arm64-virtual-blr-metadata-exact',
                                  'targetRva': int(target_rva),
                                  'targetMetadataMethodId': int(target_method_id),
                                  'proof': 'receiver-type+metadata-vtable+unique-base-intersection'})
        exact_rvas = {int(x['callRva']) for x in exact}
        review = [x for x in enriched if int(x.get('callRva', -1)) not in exact_rvas]
        return {'exactCalls': exact, 'reviewCandidates': review, 'receiverGroups': group_reports,
                'stats': {'candidates': len(calls), 'receiverTyped': receiver_typed,
                          'exact': len(exact), 'receiverGroups': len(groups),
                          'uniqueBaseGroups': sum(1 for g in group_reports if g.get('vtableBaseOffset') is not None)}}
    finally:
        meta.close()
        if elf:
            elf.close()


def _finalize_metadata_method_catalog(base_path, output_path, observed_counts=None,
                                      observed_first_refs=None, typed_methods=None, cb=None):
    """Enrich the full metadata JSONL catalogue without loading it into RAM.

    The base catalogue contains one row per metadata method and only mapping-level
    facts.  This second streaming pass overlays name-independent native BL
    observations and the bounded typed-ABI window.  Methods outside that window
    remain visible with ``abiStatus=not-materialized`` instead of disappearing.
    """
    base_path = Path(base_path)
    output_path = Path(output_path)
    if not base_path.is_file():
        return {'available': False, 'error': 'base-catalog-missing'}
    observed_counts = {int(k): int(v) for k, v in (observed_counts or {}).items() if int(v) > 0}
    observed_first_refs = observed_first_refs or {}
    typed_by_id = {}
    for item in typed_methods or ():
        mid = item.get('metadata_method_id')
        if mid is None:
            continue
        typed_by_id[int(mid)] = item

    stats = collections.Counter()
    temp = str(output_path) + '.tmp'
    page_size = 30
    # dev27 deliberately separates two unrelated indices:
    #   .idx       = dense metadataMethodId -> JSONL byte offset
    #   .pages.idx = UI page -> JSONL byte offset
    # A third sorted sidecar accelerates RVA -> metadataMethodId lookup.
    dense_index_path = Path(str(output_path) + '.idx')
    dense_index_temp = str(dense_index_path) + '.tmp'
    page_index_path = Path(str(output_path) + '.pages.idx')
    page_index_temp = str(page_index_path) + '.tmp'
    rva_index_path = Path(str(output_path) + '.rva.idx')
    rva_index_temp = str(rva_index_path) + '.tmp'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    byte_offset = 0
    missing_offset = (1 << 64) - 1
    dense_offsets = []
    rva_pairs = []
    try:
        # Large dev27 catalogues are already complete address inventories. Avoid
        # parsing and re-serializing 150k+ unchanged JSON objects just to attach
        # bounded evidence. Rows without an observed/native or typed overlay are
        # copied byte-for-byte; this also keeps the file substantially smaller.
        fast_large = base_path.stat().st_size >= 64 * 1024 * 1024
        import re as _re
        _mid_rx = _re.compile(br'\"metadata_method_id\":(-?\d+)') if fast_large else None
        _rva_rx = _re.compile(br'\"rva\":(null|-?\d+)') if fast_large else None
        # Write JSONL as bytes so every sidecar contains true byte offsets.
        with base_path.open('rb') as src, open(temp, 'wb') as dst, open(page_index_temp, 'wb') as page_index:
            for n, line in enumerate(src):
                if n % 4096 == 0:
                    check(cb)
                if not line.strip():
                    continue
                if fast_large:
                    mm = _mid_rx.search(line)
                    rm = _rva_rx.search(line)
                    mid = int(mm.group(1)) if mm else -1
                    raw_rva = rm.group(1) if rm else b'null'
                    rva = None if raw_rva == b'null' else int(raw_rva)
                    incoming = int(observed_counts.get(int(rva), 0)) if isinstance(rva, int) and rva > 0 else 0
                    typed = typed_by_id.get(mid)
                    # For 100k+ method titles the full catalogue is the immutable
                    # identity/address layer. Relations, typed ABI and context live
                    # in the bounded callable inventory + Evidence Graph sidecars.
                    # Do not rewrite tens of thousands of rows here.
                    if incoming:
                        stats['direct_bl_observed_rows'] += 1
                    if typed is not None:
                        stats['typed_window_rows'] += 1
                    if b'\"address_confirmed\":true' in line:
                        stats['address_confirmed_rows'] += 1
                    else:
                        stats['mapping_review_rows'] += 1
                    if b'\"application_owned\":true' in line:
                        stats['application_owned_rows'] += 1
                    if b'\"generic\":true' in line:
                        stats['generic_rows'] += 1
                    if b'\"abstract\":true' in line:
                        stats['abstract_rows'] += 1
                    if b'\"abi_materialized\":true' in line:
                        stats['abi_materialized_rows'] += 1
                    if b'\"abi_shape_supported\":true' in line:
                        stats['abi_shape_supported_rows'] += 1
                    if int(stats['rows']) % page_size == 0:
                        page_index.write(struct.pack('>Q', byte_offset))
                    if mid >= 0:
                        if mid >= len(dense_offsets):
                            dense_offsets.extend([missing_offset] * (mid + 1 - len(dense_offsets)))
                        if dense_offsets[mid] != missing_offset:
                            raise ValueError('Повторяющийся metadataMethodId в полном каталоге')
                        dense_offsets[mid] = byte_offset
                    if isinstance(rva, int) and rva > 0 and b'\"address_confirmed\":true' in line:
                        rva_pairs.append((int(rva), mid))
                    encoded = line if line.endswith(b'\n') else line + b'\n'
                    dst.write(encoded)
                    byte_offset += len(encoded)
                    stats['rows'] += 1
                    continue
                else:
                    row = json.loads(line)
                    mid = int(row.get('metadata_method_id', -1))
                    rva = row.get('rva')
                    incoming = int(observed_counts.get(int(rva), 0)) if isinstance(rva, int) and rva > 0 else 0
                if incoming:
                    row['static_incoming_direct_bl_count'] = incoming
                    row['static_first_call_rva'] = (observed_first_refs.get(int(rva)) or {}).get('callRva')
                    row['relation_status'] = 'observed-static-xref'
                    row['discovery_reason'] = 'exact-metadata-rva-observed-as-direct-bl-target'
                    stats['direct_bl_observed_rows'] += 1
                typed = typed_by_id.get(mid)
                if typed is not None:
                    contract = typed.get('signature_contract') or {}
                    verification = typed.get('method_verification') or {}
                    row['typed_abi'] = True
                    row['typed_window'] = True
                    row['kind'] = typed.get('kind') or row.get('kind')
                    row['method_role'] = typed.get('method_role') or row.get('method_role')
                    row['return_type'] = contract.get('metadataReturnType') or typed.get('kind')
                    params = contract.get('metadataParameters') or []
                    row['parameter_types'] = [
                        (param.get('primitive') or param.get('typeClass') or
                         ('type#' + str(param.get('typeCode')) if param.get('typeCode') is not None else '?'))
                        for param in params[:16]
                    ]
                    row['binding_suggestion'] = contract.get('bindingSuggestion')
                    row['binding_blocker'] = contract.get('bindingBlocker')
                    row['method_verification'] = verification
                    row['discovery_reason'] = typed.get('discovery_reason') or row.get('discovery_reason')
                    stats['typed_window_rows'] += 1
                    if row.get('abi_materialized'):
                        stats['abi_materialized_rows'] += 1
                    if row.get('abi_shape_supported'):
                        stats['abi_shape_supported_rows'] += 1
                    if verification.get('executableReady'):
                        stats['executable_ready_rows'] += 1
                else:
                    # dev22: the full catalogue already materializes type shapes
                    # row-by-row. The bounded typed window is retained only for
                    # deeper resolver/context work, not as an ABI visibility gate.
                    confirmed = bool(row.get('address_confirmed'))
                    abi_materialized = bool(row.get('abi_materialized'))
                    shape_supported = bool(row.get('abi_shape_supported'))
                    binding = row.get('binding_suggestion')
                    blocker = row.get('binding_blocker')
                    is_static = bool(row.get('is_static'))
                    abi_confirmed = bool(abi_materialized and shape_supported)
                    callable_ready = bool(confirmed and abi_confirmed and is_static
                                          and blocker not in {'generic-or-abstract-method',
                                                              'metadata-primitive-signature-unsupported',
                                                              'metadata-dump-signature-mismatch'})
                    if abi_confirmed and not is_static:
                        blocker = blocker or 'instance-method-needs-confirmed-instance-resolver'
                    elif abi_confirmed and not binding and not row.get('resolver_suggestion') and not blocker:
                        blocker = 'method-intent-unproven-for-auto-binding'
                    binding_ready = bool(binding and not blocker and is_static)
                    executable_ready = bool(callable_ready and binding_ready)
                    score = 0.60 if confirmed else 0.18
                    if abi_materialized:
                        score += 0.05
                    if shape_supported:
                        score += 0.06
                    if binding:
                        score += 0.04
                    if incoming:
                        score += min(0.10, 0.05 + 0.01 * min(incoming, 5))
                    row['typed_abi'] = abi_materialized
                    row['typed_window'] = False
                    if executable_ready:
                        level = 'executable-ready-static'
                    elif callable_ready:
                        level = 'callable-abi-confirmed'
                    elif confirmed and abi_confirmed:
                        level = 'callable-structural'
                    elif confirmed and incoming:
                        level = 'address-confirmed-xref-observed'
                    elif confirmed:
                        level = 'address-confirmed'
                    else:
                        level = 'review'
                    row['method_verification'] = {
                        'schema': 'modkit-method-verification-1.0',
                        'confirmationLevel': level,
                        'addressStatus': 'confirmed' if confirmed else 'review',
                        'abiStatus': ('confirmed' if abi_confirmed else
                                      'unsupported' if abi_materialized and not shape_supported else
                                      'materialized-review' if abi_materialized else 'not-materialized'),
                        'relationStatus': 'observed-static-xref' if incoming else 'not-observed',
                        'contextStatus': 'not-analyzed',
                        'semanticStatus': 'unclassified',
                        'runtimeStatus': 'not-observed',
                        'structuralConfidence': round(min(0.99, score), 2),
                        'addressConfirmed': confirmed,
                        'abiConfirmed': abi_confirmed,
                        'callableReady': callable_ready,
                        'bindingReady': binding_ready,
                        'executableReady': executable_ready,
                        'runtimeConfirmed': False,
                        'bindingSuggestion': binding,
                        'bindingBlocker': blocker,
                    }
                    if abi_materialized:
                        stats['abi_materialized_rows'] += 1
                    if shape_supported:
                        stats['abi_shape_supported_rows'] += 1
                    if executable_ready:
                        stats['executable_ready_rows'] += 1
                if row.get('address_confirmed'):
                    stats['address_confirmed_rows'] += 1
                else:
                    stats['mapping_review_rows'] += 1
                if row.get('application_owned'):
                    stats['application_owned_rows'] += 1
                if row.get('generic'):
                    stats['generic_rows'] += 1
                if row.get('abstract'):
                    stats['abstract_rows'] += 1
                if int(stats['rows']) % page_size == 0:
                    page_index.write(struct.pack('>Q', byte_offset))
                encoded = (json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
                # Dense method index is independent of physical JSONL order.
                if mid >= 0:
                    if mid >= len(dense_offsets):
                        dense_offsets.extend([missing_offset] * (mid + 1 - len(dense_offsets)))
                    if dense_offsets[mid] != missing_offset:
                        raise ValueError('Повторяющийся metadataMethodId в полном каталоге')
                    dense_offsets[mid] = byte_offset
                if isinstance(rva, int) and rva > 0 and row.get('address_confirmed'):
                    rva_pairs.append((int(rva), mid))
                dst.write(encoded)
                byte_offset += len(encoded)
                stats['rows'] += 1
        with open(dense_index_temp, 'wb') as dense_index:
            for off in dense_offsets:
                dense_index.write(struct.pack('>Q', int(off)))
        with open(rva_index_temp, 'wb') as rva_index:
            for resolved_rva, resolved_mid in sorted(rva_pairs):
                rva_index.write(struct.pack('>QI', int(resolved_rva), int(resolved_mid)))
        os.replace(temp, output_path)
        os.replace(dense_index_temp, dense_index_path)
        os.replace(page_index_temp, page_index_path)
        os.replace(rva_index_temp, rva_index_path)
    except Exception:
        for pending in (temp, dense_index_temp, page_index_temp, rva_index_temp):
            try:
                os.unlink(pending)
            except FileNotFoundError:
                pass
        raise
    finally:
        try:
            base_path.unlink()
        except FileNotFoundError:
            pass
    return {
        'available': True,
        'schema': 'modkit-full-metadata-method-catalog-1.0',
        'file': output_path.name,
        'rows': int(stats['rows']),
        'addressConfirmed': int(stats['address_confirmed_rows']),
        'mappingReview': int(stats['mapping_review_rows']),
        'directBlObserved': int(stats['direct_bl_observed_rows']),
        'abiMaterialized': int(stats['abi_materialized_rows']),
        'abiShapeSupported': int(stats['abi_shape_supported_rows']),
        'typedWindow': int(stats['typed_window_rows']),
        'typedAbi': int(stats['abi_shape_supported_rows']),
        'executableReady': int(stats['executable_ready_rows']),
        'applicationOwned': int(stats['application_owned_rows']),
        'generic': int(stats['generic_rows']),
        'abstract': int(stats['abstract_rows']),
        'storage': 'jsonl-file-backed',
        'pageSize': page_size,
        'pageCount': ((int(stats['rows']) + page_size - 1) // page_size),
        'methodIdIndexFile': dense_index_path.name,
        'methodIdIndexEncoding': 'big-endian-u64-byte-offset; UINT64_MAX=missing',
        'rvaIndexFile': rva_index_path.name,
        'rvaIndexEncoding': 'sorted-big-endian-(u64-rva,u32-method-id)',
        'pageIndexFile': page_index_path.name,
        'runtimeTruth': 'not-observed-by-static-analysis',
    }


def _catalog_method_by_id(catalog_path, metadata_method_id):
    """O(1) lookup from the dev27 dense method-id sidecar."""
    catalog_path = Path(catalog_path)
    index_path = Path(str(catalog_path) + '.idx')
    mid = int(metadata_method_id)
    if mid < 0 or not catalog_path.is_file() or not index_path.is_file():
        return None
    with index_path.open('rb') as ix:
        ix.seek(mid * 8)
        raw = ix.read(8)
    if len(raw) != 8:
        return None
    off = struct.unpack('>Q', raw)[0]
    if off == (1 << 64) - 1:
        return None
    with catalog_path.open('rb') as src:
        src.seek(off)
        line = src.readline()
    if not line:
        return None
    row = json.loads(line.decode('utf-8'))
    if int(row.get('metadata_method_id', -1)) != mid:
        raise ValueError('Dense catalog index points to a different metadataMethodId')
    return row


def _catalog_method_id_by_rva(catalog_path, rva):
    """Binary-search the sorted dev27 RVA sidecar."""
    path = Path(str(catalog_path) + '.rva.idx')
    target = int(rva or 0)
    if target <= 0 or not path.is_file():
        return None
    stride = 12
    size = path.stat().st_size
    count = size // stride
    if size % stride:
        raise ValueError('Повреждённый RVA-index каталога')
    lo, hi = 0, count
    with path.open('rb') as f:
        while lo < hi:
            mid = (lo + hi) // 2
            f.seek(mid * stride)
            raw = f.read(stride)
            if len(raw) != stride:
                return None
            rv, method_id = struct.unpack('>QI', raw)
            if rv < target:
                lo = mid + 1
            else:
                hi = mid
        if lo >= count:
            return None
        f.seek(lo * stride)
        raw = f.read(stride)
        rv, method_id = struct.unpack('>QI', raw)
        return int(method_id) if int(rv) == target else None


def _metadata_callsite_sources(metadata_path, library_path, call_rvas, cb=None,
                               selected_method_rvas=None, return_context=False,
                               max_context_methods=64, max_method_bytes=16 * 1024,
                               max_total_context_bytes=256 * 1024):
    """Attribute native call RVAs to exact managed method intervals.

    Dev16 keeps the exact dev15 semantics but avoids retaining a 150k+ list of
    metadata row dictionaries and a parallel address list.  Metadata is streamed
    in a few bounded passes: discover modules/count RVAs, collect only requested
    caller/selected rows, then resolve only actually observed callees.

    Deep method context is intentionally budgeted.  Oversized/generated methods
    remain visible as review evidence but are not scanned instruction-by-
    instruction without a bound.
    """
    import gc
    calls = sorted({int(x) for x in call_rvas if int(x) > 0})
    selected = sorted({int(x) for x in (selected_method_rvas or []) if int(x) > 0})
    if not calls and not selected:
        return ({}, {}) if return_context else {}
    meta = Metadata(metadata_path)
    elf = None
    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    try:
        elf = Elf(library_path, cb)

        # Pass 1: image/token bounds only.  This is enough to validate the
        # Il2CppCodeGenModule tables without materializing all method rows.
        token_max = collections.defaultdict(int)
        token_seen = set()
        for row in meta.iter_rows(cb):
            key = (row['image'], row['token'])
            if key in token_seen:
                continue
            token_seen.add(key)
            token_max[row['image']] = max(token_max[row['image']], row['token'] & 0xffffff)
        modules = elf.modules(set(token_max))
        modules = {name: table for name, table in modules.items() if table[0] == token_max[name]}
        token_seen.clear()

        def row_addr(row):
            module = modules.get(row['image'])
            rid = row['token'] & 0xffffff
            if not module or not 0 < rid <= module[0]:
                return 0
            addr = elf.ptr(module[1] + (rid - 1) * 8)
            if not addr:
                return 0
            try:
                elf.offset(addr, 4, True)
            except ValueError:
                return 0
            return int(addr)

        # Pass 2: numeric address multiplicity only.  Counter entries are far
        # smaller than keeping one Python dict and one int object per method.
        counts = collections.Counter()
        for i, row in enumerate(meta.iter_rows(cb)):
            if i % 4096 == 0:
                check(cb)
            addr = row_addr(row)
            if addr:
                counts[addr] += 1
        starts = sorted(counts)

        requested_starts = set()
        intervals = {}
        for call_rva in calls:
            ix = bisect.bisect_right(starts, call_rva) - 1
            if ix < 0 or ix + 1 >= len(starts):
                continue
            start = starts[ix]
            next_start = starts[ix + 1]
            if start <= call_rva < next_start:
                requested_starts.add(start)
                intervals[call_rva] = (start, next_start)

        selected = selected[:max(0, int(max_context_methods))]
        selected_set = set(selected)
        rows_at = collections.defaultdict(list)
        selected_rows = {}

        # Pass 3: retain only rows needed by caller attribution or deep context.
        wanted_row_rvas = requested_starts | selected_set
        if wanted_row_rvas:
            for i, row in enumerate(meta.iter_rows(cb)):
                if i % 4096 == 0:
                    check(cb)
                addr = row_addr(row)
                if addr not in wanted_row_rvas or counts.get(addr) != 1:
                    continue
                provenance = _il2cpp_provenance(row.get('image'), row.get('cls'))
                compact = {
                    'label': row['cls'] + '::' + row['name'],
                    'image': row['image'], 'rva': addr,
                    'metadataToken': row.get('token'), 'metadataMethodId': row.get('id'),
                    'declaringTypeIndex': row.get('declaring_type_index'),
                    'isStatic': bool(row.get('is_static')), 'isVirtual': bool(row.get('virtual')),
                    'parameterStart': row.get('parameter_start'), 'arity': row.get('args'),
                    'applicationOwned': provenance in {'game-primary', 'mixed-firstpass', 'custom-unknown'},
                    'provenance': provenance,
                    'semantic': _semantic_tags(row['cls'] + '::' + row['name']),
                }
                if addr in requested_starts:
                    rows_at[addr].append(compact)
                if addr in selected_set:
                    # Deep context needs staticness as well as compact identity.
                    selected_rows[addr] = {**row, '_compact': compact}

        result = {}
        for call_rva, (start, next_start) in intervals.items():
            source_rows = rows_at.get(start, [])
            if len(source_rows) != 1:
                continue
            result[call_rva] = {
                'sourceMethodCandidates': source_rows,
                'sourceInterval': {'startRva': start, 'nextMethodRva': next_start, 'callOffset': call_rva - start},
                'sourceAttribution': 'unique-metadata-method-interval',
            }

        if not return_context:
            return result

        raw_context = {}
        wanted_callees = set()
        total_context_bytes = 0

        def printable_data_string(target_rva):
            seg = None
            for va, off, size, flags in elf.segments:
                if va <= target_rva < va + size:
                    seg = (va, off, size, flags)
                    break
            if seg is None or (seg[3] & 1):
                return None
            try:
                off = elf.offset(target_rva, 1, False)
            except ValueError:
                return None
            end_limit = min(len(elf.b), off + 240)
            end = elf.b.find(b'\0', off, end_limit)
            if end < 0 or not 4 <= end - off <= 200:
                return None
            raw = bytes(elf.b[off:end])
            if any(b < 0x20 or b > 0x7e for b in raw):
                return None
            try:
                return raw.decode('utf-8', 'strict')
            except UnicodeDecodeError:
                return None

        for n, method_rva in enumerate(selected):
            if n % 16 == 0:
                check(cb)
            row = selected_rows.get(method_rva)
            if row is None or counts.get(method_rva) != 1:
                continue
            ix = bisect.bisect_left(starts, method_rva)
            if ix < 0 or ix + 1 >= len(starts) or starts[ix] != method_rva:
                continue
            next_start = starts[ix + 1]
            span = next_start - method_rva
            compact = row['_compact']
            base_ctx = {
                'method': {**compact, 'isStatic': bool(row.get('is_static'))},
                'interval': {'startRva': method_rva, 'nextMethodRva': next_start, 'size': span},
                'outgoingManagedCalls': [], 'outgoingIndirectCalls': [],
                'virtualDispatchCandidates': [], 'stringRefs': [], 'thisOffsetCandidates': [],
            }
            if span < 4:
                base_ctx['contextSkipped'] = 'invalid-or-empty-managed-interval'
                raw_context[method_rva] = base_ctx
                continue
            if span > int(max_method_bytes):
                base_ctx['contextSkipped'] = 'managed-interval-over-per-method-budget'
                raw_context[method_rva] = base_ctx
                continue
            if total_context_bytes + span > int(max_total_context_bytes):
                base_ctx['contextSkipped'] = 'aggregate-method-context-budget-reached'
                raw_context[method_rva] = base_ctx
                continue
            try:
                off = elf.offset(method_rva, span, True)
            except ValueError:
                base_ctx['contextSkipped'] = 'managed-interval-outside-executable-segment'
                raw_context[method_rva] = base_ctx
                continue
            total_context_bytes += span
            raw = elf.b[off:off + span]
            outgoing = []
            strings = []
            fields = []
            seen_string = set()
            seen_field = set()
            first_bl_rel = None

            words_count = len(raw) // 4
            for wi in range(words_count):
                rel = wi * 4
                word = struct.unpack_from('<I', raw, rel)[0]
                pc = method_rva + rel

                if word & 0xFC000000 == 0x94000000:
                    if first_bl_rel is None:
                        first_bl_rel = rel
                    imm26 = word & 0x03FFFFFF
                    if imm26 & 0x02000000:
                        imm26 -= 0x04000000
                    target = pc + (imm26 << 2)
                    wanted_callees.add(target)
                    if len(outgoing) < 48:
                        outgoing.append({'callRva': pc, 'targetRva': target, 'kind': 'arm64-direct-bl'})

                if word & 0x9F000000 == 0x90000000 and len(strings) < 24:
                    rd = word & 0x1F
                    immlo = (word >> 29) & 0x3
                    immhi = (word >> 5) & 0x7FFFF
                    imm21 = (immhi << 2) | immlo
                    if imm21 & (1 << 20):
                        imm21 -= 1 << 21
                    page = (pc & ~0xFFF) + (imm21 << 12)
                    for wj in range(wi + 1, min(wi + 5, words_count)):
                        w2 = struct.unpack_from('<I', raw, wj * 4)[0]
                        if w2 & 0x7F000000 != 0x11000000:
                            continue
                        rn = (w2 >> 5) & 0x1F
                        rd2 = w2 & 0x1F
                        if rn != rd or rd2 != rd:
                            continue
                        imm12 = (w2 >> 10) & 0xFFF
                        shift = 12 if ((w2 >> 22) & 1) else 0
                        target = page + (imm12 << shift)
                        text = printable_data_string(target)
                        if text and (target, text) not in seen_string:
                            seen_string.add((target, text))
                            strings.append({'xrefRva': pc, 'targetRva': target, 'value': text,
                                            'kind': 'arm64-adrp-add-string'})
                        break

                before_first_call = first_bl_rel is None or rel < first_bl_rel
                if (not row.get('is_static') and before_first_call and rel < 128
                        and (word & 0x3B000000) == 0x39000000):
                    opc = (word >> 22) & 0x3
                    rn = (word >> 5) & 0x1F
                    if opc in (0, 1) and rn == 0:
                        size_code = (word >> 30) & 0x3
                        imm12 = (word >> 10) & 0xFFF
                        field_off = imm12 << size_code
                        access = 'load' if opc == 1 else 'store'
                        key = (field_off, access, 8 << size_code)
                        if key not in seen_field and len(fields) < 24:
                            seen_field.add(key)
                            fields.append({'instructionRva': pc, 'offset': field_off,
                                           'access': access, 'widthBits': 8 << size_code,
                                           'kind': 'this-relative-offset-candidate'})

            base_ctx['outgoingManagedCalls'] = outgoing
            base_ctx['stringRefs'] = strings
            base_ctx['thisOffsetCandidates'] = fields
            try:
                from modkit.reworkspace.arm64_flow import method_indirect_calls
                indirect_ctx = method_indirect_calls(elf, method_rva, next_start, max_bytes=max_method_bytes)
                base_ctx['outgoingIndirectCalls'] = list(indirect_ctx.get('exact') or [])[:24]
                for indirect_call in base_ctx['outgoingIndirectCalls']:
                    if int(indirect_call.get('targetRva') or 0) > 0:
                        wanted_callees.add(int(indirect_call['targetRva']))
                base_ctx['virtualDispatchCandidates'] = list(indirect_ctx.get('virtualCandidates') or [])[:24]
                base_ctx['indirectCallScan'] = {
                    'strategy': indirect_ctx.get('strategy'),
                    'scannedBytes': indirect_ctx.get('scannedBytes', 0),
                    'unresolved': len(indirect_ctx.get('unresolved') or []),
                    'skipped': indirect_ctx.get('skipped'),
                }
            except Exception as indirect_exc:
                base_ctx['indirectCallScan'] = {'error': str(indirect_exc)}
            raw_context[method_rva] = base_ctx

        callee_rows = {}
        if wanted_callees:
            for i, row in enumerate(meta.iter_rows(cb)):
                if i % 4096 == 0:
                    check(cb)
                addr = row_addr(row)
                if addr not in wanted_callees or counts.get(addr) != 1:
                    continue
                provenance = _il2cpp_provenance(row.get('image'), row.get('cls'))
                callee_rows[addr] = {
                    'label': row['cls'] + '::' + row['name'], 'image': row['image'], 'rva': addr,
                    'metadataToken': row.get('token'), 'metadataMethodId': row.get('id'),
                    'applicationOwned': provenance in {'game-primary', 'mixed-firstpass', 'custom-unknown'},
                    'provenance': provenance,
                    'semantic': _semantic_tags(row['cls'] + '::' + row['name']),
                }

        for ctx in raw_context.values():
            resolved = []
            for call in ctx['outgoingManagedCalls']:
                target = callee_rows.get(call['targetRva'])
                if target:
                    resolved.append({**call, 'targetMethod': target})
            ctx['outgoingManagedCalls'] = resolved[:24]
            resolved_indirect = []
            for call in ctx.get('outgoingIndirectCalls') or []:
                target = callee_rows.get(int(call.get('targetRva') or 0))
                if target:
                    resolved_indirect.append({**call, 'targetMethod': target})
                else:
                    resolved_indirect.append(call)
            ctx['outgoingIndirectCalls'] = resolved_indirect[:24]

        return result, raw_context
    finally:
        meta.close()
        if elf:
            elf.close()
        if gc_was_enabled:
            gc.enable()

def _global_pointer_return_proof(elf, method_rva, next_rva=None, *, max_bytes=96):
    """Conservatively prove a tiny ``return global_ptr`` ARM64 shape.

    This is used only as one static proof for an obfuscated instance resolver.
    Metadata must independently prove that the method returns the exact target
    managed type.  No target code is executed.
    """
    method_rva = int(method_rva or 0)
    if method_rva <= 0:
        return {'verified': False, 'reason': 'missing-rva'}
    span = int(max_bytes)
    if isinstance(next_rva, int) and next_rva > method_rva:
        span = min(span, next_rva - method_rva)
    span &= ~3
    if span < 8:
        return {'verified': False, 'reason': 'method-interval-too-small'}
    try:
        off = elf.offset(method_rva, span, True)
    except ValueError:
        return {'verified': False, 'reason': 'method-outside-executable-segment'}
    raw = elf.b[off:off + span]
    page_regs = {}
    value_regs = {}
    saw_call = False
    loaded_slot = None
    loaded_at = None
    ret_at = None
    for rel in range(0, len(raw) - 3, 4):
        word = struct.unpack_from('<I', raw, rel)[0]
        pc = method_rva + rel
        if word & 0xFC000000 == 0x94000000:
            saw_call = True
        # ADRP Xd, page
        if word & 0x9F000000 == 0x90000000:
            rd = word & 0x1F
            immlo = (word >> 29) & 0x3
            immhi = (word >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= 1 << 21
            page_regs[rd] = (pc & ~0xFFF) + (imm21 << 12)
            value_regs.pop(rd, None)
            continue
        # ADD Xd, Xn, #imm12{, LSL #12}
        if word & 0x7F000000 == 0x11000000:
            rn = (word >> 5) & 0x1F
            rd = word & 0x1F
            base = value_regs.get(rn, page_regs.get(rn))
            if base is not None:
                imm12 = (word >> 10) & 0xFFF
                shift = 12 if ((word >> 22) & 1) else 0
                value_regs[rd] = int(base) + (imm12 << shift)
            continue
        # LDR Xt, [Xn, #imm12*8] (64-bit unsigned offset)
        if word & 0xFFC00000 == 0xF9400000:
            rn = (word >> 5) & 0x1F
            rt = word & 0x1F
            base = value_regs.get(rn, page_regs.get(rn))
            if base is not None and rt == 0:
                slot = int(base) + (((word >> 10) & 0xFFF) * 8)
                try:
                    elf.offset(slot, 8, False)
                except ValueError:
                    continue
                # The slot itself must be data, not executable code.
                seg_flags = None
                for va, _off, size, flags in elf.segments:
                    if va <= slot < va + size:
                        seg_flags = flags
                        break
                if seg_flags is not None and not (seg_flags & 1):
                    loaded_slot = slot
                    loaded_at = pc
            continue
        if word == 0xD65F03C0:  # RET X30
            ret_at = pc
            break
    if loaded_slot is not None and ret_at is not None and not saw_call:
        return {
            'verified': True,
            'kind': 'global-pointer-return',
            'slotRva': loaded_slot,
            'loadRva': loaded_at,
            'retRva': ret_at,
            'rationale': 'metadata return type + ADRP/ADD/LDR X0 from non-executable global slot + RET, no BL before return',
        }
    return {
        'verified': False,
        'reason': ('contains-call-before-return' if saw_call else
                   'global-pointer-return-shape-not-observed'),
    }


def _deep_materialize_target_and_resolvers(metadata_path, elf, metadata_method_id, cb=None,
                                             *, max_resolver_candidates=8192):
    """Materialize one exact metadata method and structural resolver candidates.

    Selection is by ``metadata_method_id`` rather than name/class/arity. This
    deliberately handles overloaded or obfuscated methods whose textual key is
    ambiguous. Resolver discovery also has a name-independent path: static
    methods returning the exact declaring managed type are inspected for a
    global-pointer-return implementation.
    """
    from modkit.reworkspace.method_evidence import method_role

    target_id = int(metadata_method_id)
    meta = Metadata(metadata_path)
    try:
        token_max = collections.defaultdict(int)
        token_seen = set()
        target = None
        for i, row in enumerate(meta.iter_rows(cb)):
            if i % 4096 == 0:
                check(cb)
            key = (row['image'], row['token'])
            if key not in token_seen:
                token_seen.add(key)
                token_max[row['image']] = max(token_max[row['image']], row['token'] & 0xffffff)
            if int(row['id']) == target_id:
                target = dict(row)
        if target is None:
            return None, [], {'available': False, 'error': 'metadata-method-id-not-found'}

        modules = elf.modules(set(token_max))
        modules = {name: table for name, table in modules.items() if table[0] == token_max[name]}

        def raw_addr_for(row):
            module = modules.get(row['image'])
            rid = int(row['token']) & 0xffffff
            if not module or not 0 < rid <= module[0]:
                return 0
            return int(elf.ptr(module[1] + (rid - 1) * 8) or 0)

        def addr_for(row):
            addr = raw_addr_for(row)
            if not addr:
                return 0
            try:
                elf.offset(addr, 4, True)
            except ValueError:
                return 0
            return addr

        # Find MetadataRegistration type table using only target indices. The
        # returned table still contains every runtime type and can therefore be
        # queried while scanning resolver candidates.
        max_index = max(0, int(target.get('type_index', -1)))
        for p in meta.parameters_for(target.get('parameter_start', -1), target.get('args', 0)):
            max_index = max(max_index, int(p.get('type_index', -1)))
        types = elf.type_table(meta.type_count, max_index)
        type_owners = meta.type_owners(cb) if types is not None else {}
        target_declaring_type = int(target.get('declaring_type_index', -1))

        counts = collections.Counter()
        candidates = []
        resolver_truncated = False
        for i, row in enumerate(meta.iter_rows(cb)):
            if i % 4096 == 0:
                check(cb)
            addr = addr_for(row)
            if addr:
                counts[addr] += 1
            if types is None or not row.get('is_static') or row.get('generic') or row.get('abstract'):
                continue
            # Structural resolver candidate shapes are evaluated independently of
            # names. Name morphology is retained only as supplementary evidence.
            rshape = elf.metadata_type_shape(types, row.get('type_index', -1))
            exact_return_target = bool(
                int(row.get('args') or 0) == 0 and rshape
                and rshape.get('typeDefIndex') == target_declaring_type
                and rshape.get('typeCode') in {0x11, 0x12}
            )
            exact_out_target = False
            if int(row.get('args') or 0) == 1 and rshape and rshape.get('primitive') == 'bool' and not rshape.get('byRef'):
                params = meta.parameters_for(row.get('parameter_start', -1), 1)
                if params:
                    pshape = elf.metadata_type_shape(types, params[0].get('type_index', -1))
                    exact_out_target = bool(pshape and pshape.get('byRef')
                                            and pshape.get('typeDefIndex') == target_declaring_type)
            if not (exact_return_target or exact_out_target or method_role(row.get('name', '')) == 'instance_resolver'):
                continue
            if len(candidates) >= int(max_resolver_candidates):
                resolver_truncated = True
                continue
            candidates.append((dict(row), addr, exact_return_target, exact_out_target))

        starts = sorted(counts)
        _materialize_metadata_type_shapes(meta, elf, types, type_owners, target) if types is not None else None
        target_addr = addr_for(target)
        target_unique = bool(target_addr and counts.get(target_addr) == 1)
        target_resolution = ('confirmed-unique-code-registration' if target_unique else
                             'shared-code-registration-rva' if target_addr else
                             'no-code-registration-pointer')
        target_contract = (_metadata_native_callable_contract(target, None) if types is not None else {})
        target_row = dict(
            id=target_id,
            label=target['cls'] + '::' + target['name'],
            image=target['image'],
            kind=target.get('return_primitive') or 'managed',
            rva=target_addr or None,
            offset=(elf.offset(target_addr, 4, True) if target_addr else None),
            semantic=_semantic_tags(target['cls'] + '::' + target['name']),
            item_type='method', method_role=method_role(target['name'], target_contract),
            source='global-metadata+CodeRegistration', resolution=target_resolution,
            selectable=False, callable=True, signature_contract=target_contract,
            metadata_token=target.get('token'), metadata_method_id=target_id,
            metadata_slot=int(target.get('slot') if target.get('slot') is not None else 0xFFFF),
            metadata_virtual=bool(target.get('virtual')),
            metadata_parameters=target.get('parameters', []),
            declaring_type_index=target_declaring_type,
            application_owned=_application_il2cpp_surface(target['image'], target['cls']),
            provenance=_il2cpp_provenance(target['image'], target['cls']),
        )

        resolved = []
        target_owner = (target['image'], target['cls'])
        for row, addr, exact_return_target, exact_out_target in candidates:
            if not addr or counts.get(addr) != 1:
                continue
            _materialize_metadata_type_shapes(meta, elf, types, type_owners, row)
            contract = _metadata_native_callable_contract(row, None)
            exact_contract_target = bool(
                contract.get('resolverTargetVerified')
                and contract.get('resolverTargetClass') == target['cls']
                and (not contract.get('resolverTargetImage') or contract.get('resolverTargetImage') == target['image'])
            )
            kind = ('return_ptr' if exact_return_target else
                    'out_ptr_bool' if exact_out_target else
                    contract.get('resolverSuggestion'))
            if kind not in {'return_ptr', 'out_ptr_bool'}:
                continue
            ix = bisect.bisect_right(starts, addr)
            next_rva = starts[ix] if ix < len(starts) else None
            global_proof = (_global_pointer_return_proof(elf, addr, next_rva)
                            if kind == 'return_ptr' and exact_return_target else
                            {'verified': False, 'reason': 'shape-not-global-return-candidate'})
            name_role = method_role(row['name'], contract)
            # Exact target type is mandatory. An obfuscated no-arg resolver is
            # promoted only when its machine code independently proves a global
            # pointer return. Name-compatible TryGet/GetInstance alone is review.
            exact_target_type = bool(exact_return_target or exact_out_target or exact_contract_target)
            verified = bool(exact_target_type and global_proof.get('verified'))
            confidence = 0.98 if verified else (0.82 if exact_target_type and name_role == 'instance_resolver' else 0.66)
            resolved.append({
                'verified': verified,
                'confidence': confidence,
                'kind': kind,
                'match': ('metadata-target-type-exact+global-pointer-return' if verified else
                          'metadata-target-type-exact-review' if exact_target_type else
                          'resolver-shape-review'),
                'label': row['cls'] + '::' + row['name'],
                'image': row['image'], 'rva': addr,
                'metadataMethodId': row.get('id'), 'metadataToken': row.get('token'),
                'targetClass': target_owner[1], 'targetImage': target_owner[0],
                'resolverTargetClass': contract.get('resolverTargetClass'),
                'resolverTargetImage': contract.get('resolverTargetImage'),
                'globalPointerProof': global_proof,
                'nameRole': name_role,
            })
        resolved.sort(key=lambda x: (not bool(x.get('verified')), -float(x.get('confidence') or 0.0), str(x.get('label') or '')))
        return target_row, resolved, {
            'available': True,
            'typeTableFound': types is not None,
            'modules': len(modules),
            'metadataMethodId': target_id,
            'targetAddressUnique': target_unique,
            'resolverCandidates': len(resolved),
            'verifiedResolvers': sum(1 for x in resolved if x.get('verified')),
            'resolverDiscoveryTruncated': resolver_truncated,
            'resolverPolicy': 'exact-managed-target-type; obfuscated return_ptr promoted only with global-pointer-return machine-code proof',
        }
    finally:
        meta.close()


def _catalog_method_row(catalog_path, metadata_method_id, cb=None):
    """Find one catalog row by exact metadata ID without trusting names."""
    # dev27 full catalogues carry a dense metadataMethodId -> byte offset
    # sidecar.  Prefer it; retain the streaming fallback for legacy fixtures.
    try:
        row = _catalog_method_by_id(catalog_path, metadata_method_id)
    except (OSError, ValueError, json.JSONDecodeError):
        row = None
    if row is not None:
        return row
    wanted = int(metadata_method_id)
    with open(catalog_path, 'r', encoding='utf-8') as f:
        for n, line in enumerate(f):
            if n % 4096 == 0:
                check(cb)
            if not line.strip():
                continue
            row = json.loads(line)
            if int(row.get('metadata_method_id', -1)) == wanted:
                return row
    return None


def _catalog_next_rva(catalog_path, rva):
    """Return the next exact executable metadata RVA from the sorted sidecar."""
    path = Path(str(catalog_path) + '.rva.idx')
    target = int(rva or 0)
    if target <= 0 or not path.is_file():
        return None
    stride = 12
    count = path.stat().st_size // stride
    lo, hi = 0, count
    with path.open('rb') as f:
        while lo < hi:
            mid = (lo + hi) // 2
            f.seek(mid * stride)
            raw = f.read(stride)
            if len(raw) != stride:
                return None
            rv, _ = struct.unpack('>QI', raw)
            if rv <= target:
                lo = mid + 1
            else:
                hi = mid
        if lo >= count:
            return None
        f.seek(lo * stride)
        raw = f.read(stride)
        if len(raw) != stride:
            return None
        rv, _ = struct.unpack('>QI', raw)
        return int(rv)


def _dump_target_context(dump_dir, target_label, target_arity=None, cb=None):
    """Return bounded dump.cs corroboration for one owner only."""
    if not dump_dir:
        return {'declaration': None, 'fields': []}
    root = Path(dump_dir)
    candidates = [root / 'dump.cs'] + list(root.glob('**/dump.cs'))
    dump_path = next((p for p in candidates if p.is_file()), None)
    if dump_path is None:
        return {'declaration': None, 'fields': []}
    owner = str(target_label or '').rsplit('::', 1)[0]
    method_name = str(target_label or '').rsplit('::', 1)[-1]
    # Deep resolution is on-demand; reading dump.cs once is acceptable and gives
    # us exact Rodroid declaration/staticness corroboration plus field offsets.
    raw = dump_path.read_text(encoding='utf-8', errors='replace')
    check(cb)
    declaration = None
    for decl in _dump_method_declarations(raw):
        if decl.get('cls') != owner or decl.get('name') != method_name:
            continue
        if target_arity is not None and int(decl.get('args', -1)) != int(target_arity):
            continue
        declaration = decl
        break
    fields = [x for x in _dump_field_discoveries(raw, 0)
              if str(x.get('label') or '').rsplit('.', 1)[0] == owner][:64]
    return {'declaration': declaration, 'fields': fields, 'dumpPath': str(dump_path)}



_DEEP_RESOLVER_SCHEMA = 'modkit-deep-method-resolution-1.2'
_DEEP_RESOLVER_ENGINE = 'dev27-evidence-graph-fast-v1'


def _cached_input_sha256(path, state_path, cb=None):
    """Cache expensive full-file SHA-256 by stable size+mtime identity."""
    path = Path(path)
    st = path.stat()
    key = str(path.resolve())
    state = {}
    state_path = Path(state_path)
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            state = {}
    rec = state.get(key) or {}
    if int(rec.get('size', -1)) == int(st.st_size) and int(rec.get('mtimeNs', -1)) == int(st.st_mtime_ns):
        sha = str(rec.get('sha256') or '')
        if len(sha) == 64:
            return sha, True
    sha = digest(path, cb)
    state[key] = {'size': int(st.st_size), 'mtimeNs': int(st.st_mtime_ns), 'sha256': sha}
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = str(state_path) + '.tmp'
        Path(temp).write_text(json.dumps(state, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.replace(temp, state_path)
    except OSError:
        pass
    return sha, False


def _deep_cache_identity(metadata_path, library_path, metadata_method_id, catalog_row, output_path, cb=None):
    if not output_path:
        return None
    root = Path(output_path).parent
    fp_state = root / '.input-fingerprints.json'
    meta_sha, meta_cached = _cached_input_sha256(metadata_path, fp_state, cb)
    lib_sha, lib_cached = _cached_input_sha256(library_path, fp_state, cb)
    payload = {
        'engine': _DEEP_RESOLVER_ENGINE,
        'schema': _DEEP_RESOLVER_SCHEMA,
        'metadataSha256': meta_sha,
        'librarySha256': lib_sha,
        'metadataMethodId': int(metadata_method_id),
        'metadataToken': int(catalog_row.get('metadata_token', -1)),
        'catalogRva': catalog_row.get('rva'),
        'catalogLabel': str(catalog_row.get('label') or ''),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    payload['cacheKey'] = hashlib.sha256(raw).hexdigest()
    payload['fingerprintCacheHit'] = bool(meta_cached and lib_cached)
    return payload


def _deep_cached_result(output_path, identity):
    if not output_path or not identity or not Path(output_path).is_file():
        return None
    try:
        row = json.loads(Path(output_path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if str((row.get('inputIdentity') or {}).get('cacheKey') or '') != str(identity.get('cacheKey') or ''):
        return None
    row['cache'] = {'hit': True, 'engine': _DEEP_RESOLVER_ENGINE, 'cacheKey': identity.get('cacheKey')}
    return row


_DEEP_GRAPH_CONTEXT_CACHE = {}


def _deep_graph_context(metadata_path, library_path, catalog_path, cb=None):
    """Return a verified dev27 Evidence Graph context for large catalogues.

    The graph is never trusted by filename alone.  Its manifest contains SHA-256
    identities of metadata, ELF and catalogue; expensive hashes are themselves
    cached by stable size+mtime.  Small/legacy fixtures intentionally stay on
    the full resolver path so BLR/vtable regression coverage remains unchanged.
    """
    catalog = Path(catalog_path)
    graph = catalog.with_name('analysis.evidence-graph.jsonl')
    meta_path = catalog.with_name('analysis.evidence-graph.meta.json')
    if not graph.is_file() or not Path(str(graph) + '.idx').is_file() or not meta_path.is_file():
        return None
    try:
        stats = tuple((str(Path(p).resolve()), Path(p).stat().st_size, Path(p).stat().st_mtime_ns)
                      for p in (metadata_path, library_path, catalog_path, graph, meta_path))
    except OSError:
        return None
    cache_key = stats
    cached = _DEEP_GRAPH_CONTEXT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        manifest = json.loads(meta_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if int(manifest.get('nodes') or 0) < 4096:
        return None
    expected = manifest.get('sourceIdentity') or {}
    state = catalog.parent / '.deep-graph-fingerprints.json'
    current = {}
    for key, path in (('metadataSha256', metadata_path), ('librarySha256', library_path),
                      ('catalogSha256', catalog_path)):
        sha, _ = _cached_input_sha256(path, state, cb)
        current[key] = sha
    current.update({'metadataBytes': Path(metadata_path).stat().st_size,
                    'libraryBytes': Path(library_path).stat().st_size,
                    'catalogBytes': Path(catalog_path).stat().st_size})
    if any(expected.get(k) != v for k, v in current.items()):
        return None
    resolver_path = catalog.with_name(str(manifest.get('resolverIndexFile') or 'analysis.resolver-index.json'))
    try:
        resolver_index = json.loads(resolver_path.read_text(encoding='utf-8')) if resolver_path.is_file() else {}
    except (OSError, ValueError):
        resolver_index = {}
    context = {'graphPath': graph, 'manifest': manifest, 'resolverIndex': resolver_index}
    _DEEP_GRAPH_CONTEXT_CACHE.clear()
    _DEEP_GRAPH_CONTEXT_CACHE[cache_key] = context
    return context


def _deep_type_owner(meta, type_def_index):
    """Resolve one TypeDefinition owner without building the full owner map."""
    ti = int(type_def_index)
    if not 0 <= ti < meta.type_count:
        return None
    image = None
    for pos in range(meta.images[0], sum(meta.images), 40):
        ni, _, first, count = meta.unpack('<IiII', pos)
        if int(first) <= ti < int(first) + int(count):
            image = meta.string(ni)
            break
    td = meta.type_definition(ti)
    return (image or '', td.get('label') or '')


def _deep_graph_domain_tags(domains):
    mapping = {
        'health': 'health', 'damage': 'damage', 'movement': 'movement',
        'progression': 'progression', 'currency': 'economy', 'resource': 'resource',
        'world': 'world', 'debug': 'debug', 'cooldown': 'state',
        'inventory': 'state', 'camera': 'state',
    }
    return sorted({mapping[d] for d in (domains or []) if d in mapping})


def _deep_fast_materialize_target_and_resolvers(metadata_path, elf, catalog_path, catalog_row,
                                                 metadata_method_id, graph_ctx, cb=None):
    """Materialize one ABI and its exact-type resolver candidates in O(1)/O(k)."""
    from modkit.reworkspace.method_evidence import method_role
    target_id = int(metadata_method_id)
    meta = Metadata(metadata_path)
    try:
        md = meta.method_definition(target_id)
        owner = _deep_type_owner(meta, md.get('declaringTypeIndex'))
        if owner is None:
            return None, [], {'available': False, 'error': 'declaring-type-not-found', 'fastPath': True}
        image, cls = owner
        # Catalogue identity is part of the graph hash, but compare the direct
        # metadata facts as an additional fail-closed guard.
        if int(catalog_row.get('metadata_token', -1)) != int(md.get('token', -2)):
            return None, [], {'available': False, 'error': 'metadata-token-mismatch', 'fastPath': True}
        label = cls + '::' + str(md.get('name') or '')
        if str(catalog_row.get('label') or '') != label:
            return None, [], {'available': False, 'error': 'metadata-label-mismatch', 'fastPath': True}
        rva = catalog_row.get('rva') if catalog_row.get('address_confirmed') else None
        if not isinstance(rva, int) or rva <= 0:
            return None, [], {'available': False, 'error': 'no-exact-code-registration-rva', 'fastPath': True}
        try:
            offset = elf.offset(rva, 4, True)
        except ValueError:
            return None, [], {'available': False, 'error': 'catalog-rva-not-executable', 'fastPath': True}

        table_info = (graph_ctx.get('manifest') or {}).get('typeTable') or {}
        types = None
        if int(table_info.get('count') or 0) > 0 and int(table_info.get('tableOffset') or 0) > 0:
            types = (int(table_info['count']), int(table_info['tableOffset']))
        if types is None:
            max_index = max(int(md.get('returnTypeIndex') or 0),
                            *(int(p.get('type_index') or 0) for p in meta.parameters_for(
                                md.get('parameterStart', -1), md.get('parameterCount', 0))))
            types = elf.type_table(meta.type_count, max_index)
        if types is None:
            return None, [], {'available': False, 'error': 'metadata-type-table-unavailable', 'fastPath': True}

        row = {
            'id': target_id, 'image': image or str(catalog_row.get('image') or ''),
            'cls': cls, 'name': md.get('name'), 'declaring_type_index': int(md.get('declaringTypeIndex')),
            'type_index': int(md.get('returnTypeIndex')), 'token': int(md.get('token')),
            'args': int(md.get('parameterCount') or 0), 'flags': int(md.get('flags') or 0),
            'parameter_start': int(md.get('parameterStart') or -1), 'slot': int(md.get('slot') or 0xFFFF),
            'is_static': bool(md.get('isStatic')), 'virtual': bool(md.get('isVirtual')),
            'generic': bool(int(md.get('genericContainerIndex', -1)) >= 0 or catalog_row.get('generic')),
            'abstract': bool(md.get('isAbstract')),
        }
        rshape = elf.metadata_type_shape(types, row['type_index'])
        row['return_type_shape'] = rshape
        row['return_primitive'] = (None if not rshape or rshape.get('byRef') else rshape.get('primitive'))
        row['return_type_definition_index'] = rshape.get('typeDefIndex') if rshape else None
        if isinstance(row['return_type_definition_index'], int) and 0 <= row['return_type_definition_index'] < meta.type_count:
            ret_owner = _deep_type_owner(meta, row['return_type_definition_index'])
            if ret_owner:
                row['return_type_image'], row['return_type_class'] = ret_owner
        params = meta.parameters_for(row['parameter_start'], row['args']) if row['args'] else []
        for param in params:
            shape = elf.metadata_type_shape(types, param.get('type_index', -1))
            param['type_shape'] = shape
            param['primitive'] = (None if not shape or shape.get('byRef') else shape.get('primitive'))
            param['by_ref'] = bool(shape and shape.get('byRef'))
            param['type_code'] = shape.get('typeCode') if shape else None
            param['type_definition_index'] = shape.get('typeDefIndex') if shape else None
            if isinstance(param['type_definition_index'], int) and 0 <= param['type_definition_index'] < meta.type_count:
                powner = _deep_type_owner(meta, param['type_definition_index'])
                if powner:
                    param['type_image'], param['type_class'] = powner
        row['parameters'] = params
        contract = _metadata_native_callable_contract(row, None)
        graph_row = None
        try:
            from modkit.mobile.gameplay import graph_method
            graph_row = graph_method(graph_ctx['graphPath'], target_id)
        except Exception:
            graph_row = None
        graph_domains = (graph_row or {}).get('semanticDomains') or []
        semantic = sorted(set(_semantic_tags(label)) | set(_deep_graph_domain_tags(graph_domains)))
        target_row = dict(
            id=target_id, label=label, image=row['image'], kind=row.get('return_primitive') or 'managed',
            rva=int(rva), offset=int(offset), semantic=semantic, item_type='method',
            method_role=method_role(row['name'], contract), source='global-metadata+CodeRegistration',
            resolution='confirmed-unique-code-registration', selectable=False, callable=True,
            signature_contract=contract, metadata_token=row['token'], metadata_method_id=target_id,
            metadata_slot=int(row.get('slot', 0xFFFF)), metadata_virtual=bool(row.get('virtual')),
            metadata_parameters=params, declaring_type_index=row['declaring_type_index'],
            application_owned=bool(catalog_row.get('application_owned')),
            provenance=catalog_row.get('provenance'),
        )

        resolved = []
        candidates = (graph_ctx.get('resolverIndex') or {}).get(str(row['declaring_type_index']), [])
        for candidate in candidates[:256]:
            crva = candidate.get('rva')
            if not isinstance(crva, int) or crva <= 0:
                continue
            kind = candidate.get('kind')
            global_proof = (_global_pointer_return_proof(elf, crva, _catalog_next_rva(catalog_path, crva))
                            if kind == 'return_ptr' else
                            {'verified': False, 'reason': 'out-pointer-resolver-needs-independent-machine-code-proof'})
            verified = bool(kind == 'return_ptr' and global_proof.get('verified'))
            c_label = str(candidate.get('label') or '')
            name_role = method_role(c_label)
            resolved.append({
                'verified': verified,
                'confidence': 0.98 if verified else (0.82 if name_role == 'instance_resolver' else 0.66),
                'kind': kind,
                'match': ('metadata-target-type-exact+global-pointer-return' if verified
                          else 'metadata-target-type-exact-review'),
                'label': c_label, 'image': candidate.get('image') or '', 'rva': int(crva),
                'metadataMethodId': candidate.get('metadataMethodId'), 'metadataToken': None,
                'targetClass': cls, 'targetImage': row['image'],
                'resolverTargetClass': cls, 'resolverTargetImage': row['image'],
                'globalPointerProof': global_proof, 'nameRole': name_role,
            })
        resolved.sort(key=lambda x: (not bool(x.get('verified')), -float(x.get('confidence') or 0.0), str(x.get('label') or '')))
        return target_row, resolved, {
            'available': True, 'fastPath': True, 'typeTableFound': True,
            'metadataMethodId': target_id, 'targetAddressUnique': True,
            'resolverCandidates': len(resolved),
            'verifiedResolvers': sum(1 for x in resolved if x.get('verified')),
            'resolverDiscoveryTruncated': len(candidates) > 256,
            'resolverPolicy': 'dev27 resolver index: exact managed target type; runtime/global-pointer proof remains on-demand',
        }
    finally:
        meta.close()


def _deep_graph_refs(catalog_path, target, graph_row):
    """Convert file-backed graph edges into the legacy semantic/ref shape."""
    def peer(mid):
        row = _catalog_method_row(catalog_path, int(mid))
        if not row:
            return None
        return {
            'label': row.get('label'), 'image': row.get('image'), 'rva': row.get('rva'),
            'metadataToken': row.get('metadata_token'), 'metadataMethodId': row.get('metadata_method_id'),
            'applicationOwned': bool(row.get('application_owned')), 'provenance': row.get('provenance'),
            'semantic': _semantic_tags(row.get('label') or ''),
        }
    incoming, outgoing = [], []
    for edge in (graph_row or {}).get('callers') or []:
        src = peer(edge.get('metadataMethodId'))
        if not src:
            continue
        incoming.append({
            'callRva': edge.get('callRva'), 'targetRva': target.get('rva'),
            'kind': 'arm64-direct-bl' if edge.get('kind') == 'bl' else 'arm64-tail-b-exact',
            'sourceAttribution': 'unique-metadata-method-interval',
            'sourceMethodCandidates': [src],
            'targetMethods': [{
                'label': target.get('label'), 'image': target.get('image'), 'rva': target.get('rva'),
                'metadataToken': target.get('metadata_token'), 'metadataMethodId': target.get('metadata_method_id'),
                'applicationOwned': target.get('application_owned'), 'provenance': target.get('provenance'),
                'semantic': target.get('semantic') or [],
            }],
        })
    source = {
        'label': target.get('label'), 'image': target.get('image'), 'rva': target.get('rva'),
        'metadataToken': target.get('metadata_token'), 'metadataMethodId': target.get('metadata_method_id'),
        'applicationOwned': target.get('application_owned'), 'provenance': target.get('provenance'),
        'semantic': target.get('semantic') or [],
    }
    out_calls = []
    for edge in (graph_row or {}).get('callees') or []:
        dst = peer(edge.get('metadataMethodId'))
        if not dst:
            continue
        kind = 'arm64-direct-bl' if edge.get('kind') == 'bl' else 'arm64-tail-b-exact'
        ref = {
            'callRva': edge.get('callRva'), 'targetRva': dst.get('rva'), 'kind': kind,
            'sourceAttribution': 'unique-metadata-method-interval',
            'sourceMethodCandidates': [source], 'targetMethods': [dst],
        }
        outgoing.append(ref)
        out_calls.append({'callRva': edge.get('callRva'), 'targetRva': dst.get('rva'),
                          'kind': kind, 'targetMethod': dst})
    typed = list((graph_row or {}).get('typedFieldAccesses') or [])
    method_context = {
        'method': source,
        'outgoingManagedCalls': out_calls,
        'outgoingIndirectCalls': [], 'virtualDispatchCandidates': [], 'stringRefs': [],
        'typedFieldAccesses': typed,
        'thisOffsetCandidates': [
            {'offset': x.get('fieldOffset'), 'access': x.get('access'),
             'instructionRva': x.get('instructionRva'), 'widthBits': x.get('widthBits')}
            for x in typed if x.get('baseProvenance') == 'this'
        ],
    }
    exact_fields = []
    for x in typed:
        exact_fields.append({
            'id': f"graph.field.{x.get('fieldDefinitionIndex')}",
            'label': f"{x.get('declaringType')}.{x.get('field')}", 'image': 'MetadataRegistration',
            'kind': 'runtime-field', 'item_type': 'field/property',
            'semantic': _deep_graph_domain_tags(x.get('domains') or []),
            'field_offset': x.get('fieldOffset'), 'selectable': False,
            'unavailable_reason': 'Exact runtime field evidence; executable binding requires a method',
        })
    return incoming, outgoing, method_context, exact_fields

def deep_resolve_method(metadata_path, library_path, catalog_path, metadata_method_id,
                        output_path=None, cb=None, dump_dir=None, _shared_elf=None):
    """On-demand evidence resolver for any row in the full IL2CPP catalog.

    The function is intentionally application-agnostic and fail-closed. It
    re-validates metadata identity/address against the currently selected inputs,
    attributes all bounded exact incoming BL call sites, decodes the method's own
    managed interval, discovers type-safe instance-resolver candidates, and then
    performs semantic correlation. Runtime behaviour is never claimed by this
    static workflow.
    """
    from modkit.reworkspace.method_evidence import build_method_verification, enrich_method_verification
    from modkit.reworkspace.correlate import augment_control_semantics

    catalog_row = _catalog_method_row(catalog_path, metadata_method_id, cb)
    if catalog_row is None:
        raise ValueError('Метод отсутствует в полном metadata-каталоге')
    cache_identity = _deep_cache_identity(
        metadata_path, library_path, metadata_method_id, catalog_row, output_path, cb)
    cached = _deep_cached_result(output_path, cache_identity)
    if cached is not None:
        check(cb, 'Deep Resolver: cache hit — входные IL2CPP-файлы не изменились')
        return json.dumps(cached, ensure_ascii=False, separators=(',', ':'))

    graph_ctx = _deep_graph_context(metadata_path, library_path, catalog_path, cb)
    graph_row = None
    if graph_ctx is not None:
        try:
            from modkit.mobile.gameplay import graph_method
            graph_row = graph_method(graph_ctx['graphPath'], metadata_method_id)
        except Exception:
            graph_row = None
    # Evidence Graph 1.0 currently persists exact BL/tail-B + typed fields, but
    # not full receiver/vtable BLR proof.  Keep virtual-slot methods on the
    # legacy resolver until that proof is also file-backed.
    use_graph_fast = bool(
        graph_ctx and graph_row
        and int(catalog_row.get('metadata_slot', 0xFFFF) if catalog_row.get('metadata_slot') is not None else 0xFFFF) == 0xFFFF
    )

    elf = _shared_elf if _shared_elf is not None else Elf(library_path, cb)
    owns_elf = _shared_elf is None
    try:
        check(cb, 'Deep Resolver: точная metadata/RVA/ABI проверка')
        if use_graph_fast:
            target, resolvers, materialize_stats = _deep_fast_materialize_target_and_resolvers(
                metadata_path, elf, catalog_path, catalog_row, metadata_method_id, graph_ctx, cb)
        else:
            target, resolvers, materialize_stats = _deep_materialize_target_and_resolvers(
                metadata_path, elf, metadata_method_id, cb)
        if not target:
            raise ValueError(materialize_stats.get('error') or 'Не удалось материализовать metadata-метод')

        # Protect against stale catalogs from a different metadata/library pair.
        stale_reasons = []
        if int(catalog_row.get('metadata_token', -1)) != int(target.get('metadata_token', -2)):
            stale_reasons.append('metadata-token-mismatch')
        if str(catalog_row.get('label') or '') != str(target.get('label') or ''):
            stale_reasons.append('metadata-label-mismatch')
        crva = catalog_row.get('rva')
        if isinstance(crva, int) and isinstance(target.get('rva'), int) and int(crva) != int(target['rva']):
            stale_reasons.append('code-registration-rva-mismatch')
        if stale_reasons:
            raise ValueError('Полный каталог не соответствует выбранной IL2CPP-паре: ' + ', '.join(stale_reasons))

        graph_fields = []
        if use_graph_fast:
            # Exact MetadataRegistration fields from the graph supersede the
            # expensive 50+ MiB dump.cs reparsing in the hot path.
            dump_context = {'declaration': None, 'fields': []}
        else:
            dump_context = _dump_target_context(dump_dir, target.get('label'), catalog_row.get('arity'), cb)
        decl = dump_context.get('declaration')
        if decl is not None:
            # Materialized metadata shapes are already primary ABI evidence;
            # dump.cs is only independent declaration corroboration.
            contract = dict(target.get('signature_contract') or {})
            contract['dumpDeclaration'] = decl.get('declaration', '')
            contract['dumpArityVerified'] = int(decl.get('args', -1)) == int(catalog_row.get('arity', -2))
            contract['dumpStaticnessVerified'] = bool(decl.get('declaration_static')) == bool(catalog_row.get('is_static'))
            target['signature_contract'] = contract

        verified_resolver = next((r for r in resolvers if r.get('verified')), None)
        rva = target.get('rva')
        incoming_calls = []
        incoming_virtual_candidates = []
        incoming_scan = {'scannedBytes': 0, 'matches': 0, 'truncated': False}
        caller_map = {}
        method_context = {}
        pointer_slots = []
        target_canonicalization = None
        virtual_dispatch = {'exactCalls': [], 'reviewCandidates': [], 'receiverGroups': [], 'stats': {}}
        incoming_refs = []
        outgoing_refs = []
        if use_graph_fast and isinstance(rva, int) and rva > 0:
            check(cb, 'Deep Resolver: Evidence Graph fast-path')
            incoming_refs, outgoing_refs, method_context, graph_fields = _deep_graph_refs(
                catalog_path, target, graph_row)
            incoming_calls = incoming_refs
            incoming_scan = {
                'scannedBytes': 0, 'matches': len(incoming_refs), 'truncated': False,
                'source': 'shared-evidence-graph', 'graphFastPath': True,
            }
            # A direct canonicalization is bounded to this exact method and does
            # not rescan the ELF.  Function-pointer/vtable proof remains legacy.
            from modkit.reworkspace.arm64_flow import canonicalize_thunk
            target_canonicalization = canonicalize_thunk(elf, rva)
        elif isinstance(rva, int) and rva > 0:
            from modkit.reworkspace.arm64_flow import canonicalize_thunk, function_pointer_slots
            check(cb, 'Deep Resolver: BL/BLR/thunk входящие связи')
            target_canonicalization = canonicalize_thunk(elf, rva)
            incoming_calls, incoming_virtual_candidates, incoming_scan = _arm64_extended_calls_to_target(
                elf, rva, target.get('metadata_slot'), cb)
            check(cb, 'Deep Resolver: receiver type + metadata vtable proof')
            virtual_dispatch = _resolve_virtual_dispatch_for_target(
                metadata_path, library_path, incoming_virtual_candidates,
                int(metadata_method_id), int(rva), cb)
            incoming_calls.extend(virtual_dispatch.get('exactCalls') or [])
            incoming_virtual_candidates = list(virtual_dispatch.get('reviewCandidates') or [])
            incoming_scan['virtualExactMatches'] = len(virtual_dispatch.get('exactCalls') or [])
            incoming_scan['virtualReceiverTyped'] = int((virtual_dispatch.get('stats') or {}).get('receiverTyped') or 0)
            check(cb, 'Deep Resolver: function-pointer/vtable data slots')
            pointer_slots = function_pointer_slots(elf, rva, max_results=256)
            check(cb, 'Deep Resolver: caller/callee/context attribution')
            caller_map, contexts = _metadata_callsite_sources(
                metadata_path, library_path, [x['callRva'] for x in incoming_calls], cb,
                selected_method_rvas=[rva], return_context=True,
                max_context_methods=1, max_method_bytes=64 * 1024,
                max_total_context_bytes=64 * 1024)
            method_context = contexts.get(rva) or {}

        direct_count = sum(1 for x in incoming_calls if x.get('kind') == 'arm64-direct-bl')
        thunk_count = sum(1 for x in incoming_calls if x.get('kind') == 'arm64-direct-bl-via-thunk')
        tail_count = sum(1 for x in incoming_calls if x.get('kind') == 'arm64-tail-b-exact')
        indirect_count = sum(1 for x in incoming_calls if x.get('kind') == 'arm64-indirect-blr-exact')
        virtual_exact_count = sum(1 for x in incoming_calls if x.get('kind') == 'arm64-virtual-blr-metadata-exact')
        target['static_incoming_direct_bl_count'] = direct_count
        target['static_incoming_thunk_count'] = thunk_count
        target['static_incoming_tail_b_count'] = tail_count
        target['static_incoming_indirect_count'] = indirect_count
        target['static_incoming_virtual_count'] = virtual_exact_count
        target['static_first_call_rva'] = (incoming_calls[0].get('callRva') if incoming_calls else None)
        target['target_canonicalization'] = target_canonicalization or {}
        target['function_pointer_slot_count'] = len(pointer_slots)
        verification = build_method_verification(target, verified_resolver)

        if not use_graph_fast:
            incoming_refs = []
            for call in incoming_calls:
                attributed = caller_map.get(call.get('callRva')) or {}
                incoming_refs.append({**call, **attributed})

            outgoing_refs = []
            source_compact = {
                'label': target.get('label'), 'image': target.get('image'), 'rva': target.get('rva'),
                'metadataToken': target.get('metadata_token'), 'metadataMethodId': target.get('metadata_method_id'),
                'applicationOwned': target.get('application_owned'), 'provenance': target.get('provenance'),
                'semantic': target.get('semantic') or [],
            }
            for call in (method_context.get('outgoingManagedCalls') or [])[:64]:
                peer = call.get('targetMethod') or {}
                outgoing_refs.append({
                    'callRva': call.get('callRva'), 'targetRva': call.get('targetRva'),
                    'kind': call.get('kind') or 'arm64-direct-bl',
                    'sourceAttribution': 'unique-metadata-method-interval',
                    'sourceMethodCandidates': [source_compact],
                    'targetMethods': [peer] if peer else [],
                })
            for call in (method_context.get('outgoingIndirectCalls') or [])[:64]:
                peer = call.get('targetMethod') or {}
                outgoing_refs.append({
                    'callRva': call.get('callRva'), 'targetRva': call.get('targetRva'),
                    'rawTargetRva': call.get('rawTargetRva'),
                    'kind': call.get('kind') or 'arm64-indirect-blr-exact',
                    'sourceAttribution': 'unique-metadata-method-interval',
                    'sourceMethodCandidates': [source_compact],
                    'targetMethods': [peer] if peer else [],
                    'thunk': call.get('thunk') or {},
                })

        verification = enrich_method_verification(
            verification, incoming_refs=incoming_refs, outgoing_refs=outgoing_refs,
            method_context=method_context)
        # Function-pointer slots corroborate indirect reachability but never prove
        # which unresolved virtual callsite consumed the pointer.
        if pointer_slots:
            evidence = list(verification.get('evidence') or [])
            evidence.append({'kind': 'function-pointer-data-slots', 'count': len(pointer_slots),
                             'rationale': 'non-executable ELF data contains exact pointer(s) to this method/thunk'})
            verification['evidence'] = evidence[:32]
        target['method_verification'] = verification

        # Reuse the same generic semantic fusion as RE Workspace, but on a single
        # exact target with its full on-demand relation set. Binding intent remains
        # separate from semantic classification.
        candidate = {
            'id': f'deep.{int(metadata_method_id)}',
            'title': target.get('label'), 'value': target.get('label'),
            'source': target.get('image'), 'kind': 'il2cpp-metadata-callable',
            'status': 'review', 'confidence': float(verification.get('structuralConfidence') or 0.0),
            'evidenceRva': target.get('rva'), 'evidenceCount': 1,
            'corroboratingEvidence': [], 'methodVerification': verification,
        }
        semantic_report = {
            'controlCandidates': [candidate],
            'il2cpp': {
                'metadata_callable_methods': [target],
                'metadata_resolved_methods': [],
                'discoveries': (graph_fields if use_graph_fast else (dump_context.get('fields') or [])),
                'candidates': [],
            },
            'nativeRelations': {
                # Backward-compatible semantic input: contains every *exact*
                # static call edge, including dev24 BLR/thunk edges.
                'il2cppDirectCallRefs': incoming_refs + outgoing_refs,
                'il2cppStaticCallRefs': incoming_refs + outgoing_refs,
                'il2cppVirtualDispatchCandidates': incoming_virtual_candidates + list(method_context.get('virtualDispatchCandidates') or []),
                'functionPointerSlots': pointer_slots,
                'il2cppMethodContext': [method_context] if method_context else [],
            },
            'findings': [],
        }
        augment_control_semantics(semantic_report)
        semantic = semantic_report['controlCandidates'][0]
        verification = semantic.get('methodVerification') or verification
        target['method_verification'] = verification

        context_verified = bool(semantic.get('contextVerified'))
        menu_eligible = bool(
            semantic.get('semanticVerified')
            and context_verified
            and verification.get('executableReady')
            and verification.get('bindingSuggestion')
        )
        if menu_eligible:
            menu_blocker = None
        elif not semantic.get('semanticVerified'):
            menu_blocker = semantic.get('semanticBlocker') or 'semantic-verification-required'
        elif not context_verified:
            menu_blocker = semantic.get('contextBlocker') or 'method-local-context-verification-required'
        elif not verification.get('bindingSuggestion'):
            menu_blocker = 'method-intent-unproven-for-auto-binding'
        else:
            menu_blocker = verification.get('bindingBlocker') or 'structural-callability-required'

        decision = ('menu-candidate-static-evidence' if menu_eligible else
                    'semantic-context-confirmed-review' if semantic.get('semanticVerified') and context_verified else
                    'semantic-confirmed-context-review' if semantic.get('semanticVerified') else
                    'context-correlated-review' if semantic.get('semanticStatus') == 'correlated-review' else
                    'structural-only')
        binding = verification.get('bindingSuggestion')
        params = (target.get('signature_contract') or {}).get('metadataParameters') or []
        if binding == 'action':
            suggested_type = 'button'
        elif binding == 'bool_setter':
            suggested_type = 'toggle'
        elif binding == 'number_setter':
            primitive = str((params[0] if params else {}).get('primitive') or '')
            suggested_type = 'slider_float' if primitive in {'float', 'double'} else 'slider_int'
        else:
            suggested_type = 'review'
        resolver_payload = None
        if verified_resolver:
            resolver_payload = {
                'verified': True, 'rva': verified_resolver.get('rva'),
                'kind': verified_resolver.get('kind'), 'label': verified_resolver.get('label'),
                'source': verified_resolver.get('image'), 'match': verified_resolver.get('match'),
                'targetClass': verified_resolver.get('targetClass'),
                'contractSource': 'global-metadata+CodeRegistration+machine-code-proof',
            }
        menu_candidate = ({
            'id': f'deep.method.{int(metadata_method_id)}',
            'title': target.get('label'), 'value': target.get('label'),
            'suggestedType': suggested_type, 'status': 'confirmed',
            'confidence': max(float(semantic.get('semanticConfidence') or 0.0),
                              float(verification.get('structuralConfidence') or 0.0)),
            'source': target.get('image'), 'kind': 'il2cpp-deep-resolved-method',
            'location': f"RVA 0x{int(target.get('rva')):x}" if isinstance(target.get('rva'), int) else '',
            'evidenceRva': target.get('rva'), 'evidenceCount': len(incoming_refs) + len(outgoing_refs) + 1,
            'isStatic': (target.get('signature_contract') or {}).get('isStatic'),
            'signatureContract': target.get('signature_contract') or {},
            'bindingSuggestion': binding, 'bindingBlocker': verification.get('bindingBlocker'),
            'instanceResolver': resolver_payload or {},
            'resolverRva': (verified_resolver or {}).get('rva'),
            'resolverKind': (verified_resolver or {}).get('kind'),
            'resolverVerified': bool(verified_resolver),
            'resolverMatch': (verified_resolver or {}).get('match'),
            'semanticVerified': True, 'semanticStatus': semantic.get('semanticStatus'),
            'semanticConfidence': semantic.get('semanticConfidence'),
            'semanticTags': semantic.get('semanticTags') or [],
            'semanticEvidence': semantic.get('semanticEvidence') or [],
            'semanticBlocker': semantic.get('semanticBlocker'),
            'contextVerified': True, 'contextStatus': semantic.get('contextStatus'),
            'contextConfidence': semantic.get('contextConfidence'),
            'contextEvidence': semantic.get('contextEvidence') or [],
            'contextBlocker': semantic.get('contextBlocker'),
            'corroboratingEvidence': list(verification.get('evidence') or [])[:24],
            'canonicalImplementationRva': ((target_canonicalization or {}).get('canonicalRva') if target_canonicalization else target.get('rva')),
            'methodVerification': verification,
        } if menu_eligible else None)
        result = {
            'schema': _DEEP_RESOLVER_SCHEMA,
            'metadataMethodId': int(metadata_method_id),
            'decision': decision,
            'target': target,
            'catalogSnapshot': catalog_row,
            'inputIdentity': cache_identity or {},
            'cache': {'hit': False, 'engine': _DEEP_RESOLVER_ENGINE,
                      'cacheKey': (cache_identity or {}).get('cacheKey')},
            'materialization': materialize_stats,
            'targetCanonicalization': target_canonicalization or {},
            'incomingCalls': incoming_refs[:512],
            'incomingDirectCalls': [x for x in incoming_refs if x.get('kind') == 'arm64-direct-bl'][:512],
            'incomingThunkCalls': [x for x in incoming_refs if x.get('kind') == 'arm64-direct-bl-via-thunk'][:512],
            'incomingIndirectCalls': [x for x in incoming_refs if x.get('kind') == 'arm64-indirect-blr-exact'][:512],
            'incomingVirtualCalls': [x for x in incoming_refs if x.get('kind') == 'arm64-virtual-blr-metadata-exact'][:512],
            'incomingVirtualCandidates': incoming_virtual_candidates[:512],
            'functionPointerSlots': pointer_slots[:256],
            'dispatchCorrelation': {
                'metadataSlot': target.get('metadata_slot'),
                'functionPointerSlots': len(pointer_slots),
                'virtualExactCalls': virtual_exact_count,
                'virtualCallsiteCandidates': len(incoming_virtual_candidates) + len(method_context.get('virtualDispatchCandidates') or []),
                'receiverGroups': virtual_dispatch.get('receiverGroups') or [],
                'status': ('confirmed-receiver-vtable-target' if virtual_exact_count
                           else 'correlated-review' if pointer_slots and (incoming_virtual_candidates or method_context.get('virtualDispatchCandidates'))
                           else 'data-pointer-observed' if pointer_slots
                           else 'virtual-shape-observed' if (incoming_virtual_candidates or method_context.get('virtualDispatchCandidates'))
                           else 'not-observed'),
                'confirmedExactTarget': bool(virtual_exact_count),
                'note': ('exact virtual target requires static receiver type + metadata vtable + uniquely inferred VirtualInvokeData base; '
                         'ambiguous/interface-only dispatch remains review'),
            },
            'incomingCallScan': incoming_scan,
            'methodContext': method_context,
            'instanceResolvers': resolvers[:64],
            'verifiedInstanceResolver': verified_resolver,
            'semantic': {
                'status': semantic.get('semanticStatus'),
                'verified': bool(semantic.get('semanticVerified')),
                'confidence': semantic.get('semanticConfidence'),
                'tags': semantic.get('semanticTags') or [],
                'corroboratedTags': semantic.get('semanticCorroboratedTags') or [],
                'signalSources': semantic.get('semanticSignalSources') or {},
                'evidence': semantic.get('semanticEvidence') or [],
                'blocker': semantic.get('semanticBlocker'),
            },
            'contextVerification': {
                'status': semantic.get('contextStatus'),
                'verified': context_verified,
                'confidence': semantic.get('contextConfidence'),
                'evidence': semantic.get('contextEvidence') or [],
                'blocker': semantic.get('contextBlocker'),
            },
            'methodVerification': verification,
            'menuEligibility': {
                'eligible': menu_eligible,
                'blocker': menu_blocker,
                'bindingSuggestion': verification.get('bindingSuggestion'),
                'policy': 'address+ABI/resolver + semanticVerified + contextVerified + safe binding suggestion',
            },
            'menuCandidate': menu_candidate,
            'runtimeTruth': {
                'status': 'not-observed',
                'confirmed': False,
                'note': 'Deep Resolver is static-only; runtime behaviour requires an independent runtime observation.',
            },
        }
        if output_path:
            temp = str(output_path) + '.tmp'
            Path(temp).parent.mkdir(parents=True, exist_ok=True)
            Path(temp).write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
            os.replace(temp, output_path)
        return json.dumps(result, ensure_ascii=False, separators=(',', ':'))
    finally:
        if owns_elf:
            elf.close()


def _param_count_csharp(text):
    text=str(text).strip()
    if not text:
        return 0
    depth=0; count=1
    for ch in text:
        if ch in '<[(': depth+=1
        elif ch in '>])': depth=max(0,depth-1)
        elif ch==',' and depth==0: count+=1
    return count


def _split_csharp_params(text):
    text = str(text or '').strip()
    if not text:
        return []
    result=[]; start=0; depth=0
    pairs={'<':'>','[':']','(':')'}
    opens=set(pairs); closes=set(pairs.values())
    for i,ch in enumerate(text):
        if ch in opens: depth+=1
        elif ch in closes: depth=max(0,depth-1)
        elif ch==',' and depth==0:
            result.append(text[start:i].strip()); start=i+1
    tail=text[start:].strip()
    if tail: result.append(tail)
    return result


def _dump_method_declarations(raw_dump, unresolved_only=False):
    """Yield exact dump.cs method declarations with DLL/class/arity/RVA state.

    ``unresolved_only`` preserves the legacy RVA=-1 fallback behavior. The full
    stream is also used by the dev12 callable resolver so method intent/signature
    can be correlated with the independent metadata + CodeRegistration address.
    """
    import re
    dll=namespace=owner=''; pending_rva=None
    class_re=re.compile(r'\b(?:class|struct|interface)\s+([A-Za-z_$][\w$<>`]*)')
    method_re=re.compile(
        r'^\s*(?P<mods>(?:(?:public|private|protected|internal|static|virtual|override|sealed|abstract|extern|unsafe|async|new)\s+)*)'
        r'(?P<ret>[\w.<>,\[\]?`]+)\s+(?P<name>[^\s(]+)\((?P<params>.*)\)\s*\{')
    for line in raw_dump.splitlines():
        stripped=line.strip()
        if stripped.startswith('// Dll :'):
            dll=stripped.split(':',1)[1].strip(); continue
        if stripped.startswith('// Namespace:'):
            namespace=stripped.split(':',1)[1].strip(); continue
        cm=class_re.search(stripped)
        if cm and not stripped.startswith('//'):
            owner=cm.group(1).split('<',1)[0]
        if stripped.startswith('// RVA:'):
            value=stripped.split('RVA:',1)[1].split()[0]
            pending_rva=value
            continue
        if pending_rva is None or not stripped or stripped.startswith('[') or stripped.startswith('//'):
            continue
        mm=method_re.match(line)
        if not mm:
            # Keep waiting through attributes, but a non-attribute source line
            # consumes the RVA marker to avoid attaching it to a later method.
            if not stripped.startswith('['):
                pending_rva=None
            continue
        rva_text=pending_rva; pending_rva=None
        unresolved=rva_text in ('-1','0','0x0','0x00000000')
        if unresolved_only and not unresolved:
            continue
        cls='.'.join(x for x in (namespace,owner) if x)
        params=mm.group('params')
        mods=mm.group('mods') or ''
        yield dict(image=dll, cls=cls, name=mm.group('name'), args=_param_count_csharp(params),
                   return_decl=mm.group('ret'), params_decl=params, params=_split_csharp_params(params),
                   declaration=stripped, declaration_static=bool(re.search(r'\bstatic\b', mods)),
                   dump_rva=rva_text, dump_unresolved=unresolved)


def _dump_unresolved_declarations(raw_dump):
    yield from _dump_method_declarations(raw_dump, unresolved_only=True)


def _csharp_param_shape(param):
    """Return (type, name, byref) for a C# dump parameter without guessing ABI."""
    import re
    text=re.sub(r'^\s*(?:\[[^\]]+\]\s*)+', '', str(param or '').strip())
    text=text.split('=',1)[0].strip()
    byref=False
    m=re.match(r'^(?:(out|ref|in)\s+)?(.+?)\s+([A-Za-z_$][\w$]*)$', text)
    if not m:
        return '', '', False
    mode, type_name, name=m.groups(); byref=mode in ('out','ref')
    return type_name.strip(), name, byref


def _metadata_native_callable_contract(row, decl=None):
    """Build a callable contract directly from metadata + MetadataRegistration.

    ``dump.cs`` is optional corroboration only.  Automatic bindings are produced
    exclusively for primitive ABI shapes already supported by the Menu runtime.
    """
    import re
    from modkit.reworkspace.signature import rodroid_signature_contract

    c_map = {
        'void':'void', 'bool':'bool', 'float':'float', 'double':'double',
        'int8':'int8_t', 'uint8':'uint8_t', 'int16':'int16_t', 'uint16':'uint16_t',
        'int32':'int32_t', 'uint32':'uint32_t', 'int64':'int64_t', 'uint64':'uint64_t',
    }
    method = str(row.get('name') or '')
    is_static = bool(row.get('is_static'))
    return_kind = row.get('return_primitive')
    return_shape = row.get('return_type_shape') or {}
    parameters = list(row.get('parameters') or [])
    direct_shape_supported = return_kind in c_map and all(
        p.get('primitive') in c_map and p.get('primitive') != 'void' for p in parameters)
    class_like_codes = {0x0E, 0x12, 0x15, 0x1C, 0x1D}  # string/class/genericinst/object/szarray
    resolver_shape = (is_static and return_kind == 'bool' and len(parameters) == 1
                      and str(method).casefold().startswith('tryget')
                      and bool(parameters[0].get('by_ref'))
                      and parameters[0].get('type_code') in class_like_codes)
    singleton_name = bool(re.match(r'(?i)^(?:get_?instance|getinstance|instance)$', method))
    return_ptr_shape = (is_static and len(parameters) == 0 and singleton_name
                        and return_shape.get('typeCode') in {0x11, 0x12}
                        and bool(row.get('return_type_class')))
    shape_supported = direct_shape_supported or resolver_shape or return_ptr_shape
    cparams = []
    if not is_static:
        cparams.append('void* __this')
    if resolver_shape:
        pname = re.sub(r'[^A-Za-z0-9_$]+', '_', str(parameters[0].get('name') or 'instance')) or 'instance'
        cparams.append(f'void** {pname}')
    elif direct_shape_supported:
        for i, param in enumerate(parameters):
            pname = re.sub(r'[^A-Za-z0-9_$]+', '_', str(param.get('name') or f'arg{i}')) or f'arg{i}'
            cparams.append(f"{c_map[param['primitive']]} {pname}")
    cparams.append('const MethodInfo* method')
    fn = 'Metadata__' + re.sub(r'[^A-Za-z0-9_$]+', '_', method)
    synthetic_return = 'void*' if return_ptr_shape else c_map.get(return_kind, 'void')
    synthetic = f"{synthetic_return} {fn} ({', '.join(cparams)});"
    contract = rodroid_signature_contract(synthetic)
    contract.update({
        'contractSource':'global-metadata+CodeRegistration',
        'metadataToken':row.get('token'), 'metadataMethodId':row.get('id'),
        'metadataStatic':is_static, 'staticnessVerified':True,
        'metadataReturnType':return_kind,
        'metadataReturnTypeCode':return_shape.get('typeCode'),
        'metadataReturnTypeDefinitionIndex':row.get('return_type_definition_index'),
        'metadataReturnTypeImage':row.get('return_type_image'),
        'metadataReturnTypeClass':row.get('return_type_class'),
        'metadataParameters':[{'name':p.get('name'), 'token':p.get('token'),
                               'typeIndex':p.get('type_index'), 'primitive':p.get('primitive'),
                               'typeCode':p.get('type_code'), 'byRef':bool(p.get('by_ref')),
                               'typeDefinitionIndex':p.get('type_definition_index'),
                               'typeImage':p.get('type_image'), 'typeClass':p.get('type_class')}
                              for p in parameters],
        'shapeSupported':bool(shape_supported), 'resolverShape':bool(resolver_shape),
        'returnPointerResolverShape':bool(return_ptr_shape),
        'generic':bool(row.get('generic')), 'abstract':bool(row.get('abstract')),
    })
    if resolver_shape:
        rp = parameters[0]
        contract.update({
            'resolverTargetTypeIndex': rp.get('type_definition_index'),
            'resolverTargetImage': rp.get('type_image'),
            'resolverTargetClass': rp.get('type_class'),
            'resolverTargetVerified': bool(rp.get('type_class')),
        })
    elif return_ptr_shape:
        contract.update({
            'resolverTargetTypeIndex': row.get('return_type_definition_index'),
            'resolverTargetImage': row.get('return_type_image'),
            'resolverTargetClass': row.get('return_type_class'),
            'resolverTargetVerified': bool(row.get('return_type_class')),
        })
    if decl is not None:
        contract['dumpDeclaration'] = decl.get('declaration', '')
        contract['dumpArityVerified'] = int(decl.get('args', -1)) == int(row.get('args', -2))
        contract['dumpStaticnessVerified'] = bool(decl.get('declaration_static')) == is_static
    blocker = None
    if row.get('generic') or row.get('abstract'):
        blocker = 'generic-or-abstract-method'
    elif not shape_supported:
        blocker = 'metadata-primitive-signature-unsupported'
    elif decl is not None and (not contract.get('dumpArityVerified') or not contract.get('dumpStaticnessVerified')):
        blocker = 'metadata-dump-signature-mismatch'
    if blocker:
        contract['bindingSuggestion'] = None
        contract['resolverSuggestion'] = None
        contract['autoBindingSafe'] = False
        contract['bindingBlocker'] = blocker
    return contract


def _metadata_callable_contract(decl, row):
    """Build a conservative IL2CPP callable contract from dump.cs + metadata.

    Staticness comes from MethodDefinition flags, while parameter/return shapes
    come from the human-readable dump declaration. Only the small ABI subset
    already supported by Menu Builder is promoted automatically.
    """
    import re
    from modkit.reworkspace.signature import rodroid_signature_contract

    method=str(decl.get('name') or '')
    ret=str(decl.get('return_decl') or '')
    is_static=bool(row.get('is_static'))
    params=[_csharp_param_shape(x) for x in decl.get('params', [])]
    safe_map={
        'bool':'bool','System.Boolean':'bool',
        'float':'float','System.Single':'float',
        'double':'double','System.Double':'double',
        'int':'int32_t','System.Int32':'int32_t',
        'uint':'uint32_t','System.UInt32':'uint32_t',
        'long':'int64_t','System.Int64':'int64_t',
        'ulong':'uint64_t','System.UInt64':'uint64_t',
        'short':'int16_t','System.Int16':'int16_t',
        'ushort':'uint16_t','System.UInt16':'uint16_t',
        'byte':'uint8_t','System.Byte':'uint8_t',
        'sbyte':'int8_t','System.SByte':'int8_t',
        'void':'void','System.Void':'void',
    }
    return_c=safe_map.get(ret, '')
    cparams=[]
    if not is_static:
        cparams.append('void* __this')
    shape_supported=True
    for i,(typ,name,byref) in enumerate(params):
        native=safe_map.get(typ)
        pname=name or f'arg{i}'
        if byref:
            # Resolver contract only needs an out/ref object pointer. For
            # arbitrary managed reference types we deliberately use opaque void**.
            if native:
                native += '*'
            elif typ:
                native='void**'
            else:
                shape_supported=False; break
        elif native:
            pass
        else:
            shape_supported=False; break
        cparams.append(f'{native} {pname}')
    cparams.append('const MethodInfo* method')
    fn='Metadata__'+re.sub(r'[^A-Za-z0-9_$]+','_',method)
    synthetic=f"{return_c or 'void'} {fn} ({', '.join(cparams)});"
    contract=rodroid_signature_contract(synthetic)
    contract.update({
        'contractSource':'global-metadata+dump.cs',
        'managedDeclaration':decl.get('declaration',''),
        'metadataToken':row.get('token'),
        'metadataMethodId':row.get('id'),
        'metadataStatic':is_static,
        'declarationStatic':bool(decl.get('declaration_static')),
        'staticnessVerified':bool(decl.get('declaration_static')) == is_static,
        'managedReturnType':ret,
        'managedParameters':[{'type':t,'name':n,'byRef':b} for t,n,b in params],
        'shapeSupported':shape_supported and bool(return_c),
    })
    # A contradictory dump declaration must never become executable evidence.
    if not contract['staticnessVerified'] or not contract['shapeSupported']:
        contract['bindingSuggestion']=None
        contract['resolverSuggestion']=None
        contract['autoBindingSafe']=False
        contract['bindingBlocker']='metadata-declaration-signature-mismatch' if not contract['staticnessVerified'] else 'managed-signature-shape-unsupported'
    return contract


_ANALYSIS_UI_KEYS = ('id','label','image','kind','rva','semantic','selectable','item_type',
                     'unavailable_reason','source','resolution','field_offset','provenance','application_owned',
                     'method_role','method_verification','static_incoming_direct_bl_count',
                     'static_first_call_rva','discovery_reason')

def _analysis_ui_row(item):
    row = {k:item.get(k) for k in _ANALYSIS_UI_KEYS if k in item}
    contract = item.get('signature_contract') or {}
    if contract:
        row['is_static'] = contract.get('isStatic')
        row['binding_suggestion'] = contract.get('bindingSuggestion')
        row['binding_blocker'] = contract.get('bindingBlocker')
        row['return_type'] = contract.get('metadataReturnType') or item.get('kind')
        params = contract.get('metadataParameters') or []
        row['parameter_types'] = [
            (p.get('primitive') or p.get('typeClass') or ('type#'+str(p.get('typeCode')) if p.get('typeCode') is not None else '?'))
            for p in params[:8]
        ]
    return row


def analyze_rodroid(dump_dir, metadata_path, library_path, output_path, cb=None, compact_return=False, ui_index_path=None, method_catalog_path=None):
    """Build the patch model strictly from Rodroid's script.json/dump.cs output."""
    dump_dir = Path(dump_dir)
    script_path, dump_path = dump_dir / 'script.json', dump_dir / 'dump.cs'
    if not script_path.is_file() or not dump_path.is_file():
        raise ValueError('Rodroid не создал обязательные dump.cs и script.json')
    check(cb, 'Чтение script.json Rodroid')
    script = json.loads(script_path.read_text(encoding='utf-8'))
    methods = script.get('ScriptMethod')
    addresses = sorted({int(x) for x in script.get('Addresses', []) if int(x) > 0})
    if not isinstance(methods, list):
        raise ValueError('Некорректный script.json: нет ScriptMethod')
    rodroid_method_count = len(methods)
    large_compact = bool(compact_return and rodroid_method_count > 10000)
    candidate_file = Path(output_path).with_name(Path(output_path).stem + '.candidates.jsonl')
    discovery_file = Path(output_path).with_name(Path(output_path).stem + '.discoveries.jsonl')
    ui_spool_file = Path(output_path).with_name(Path(output_path).stem + '.ui.spool.jsonl')
    initial_candidate_count = 0
    initial_discovery_count = 0
    e = Elf(library_path, cb)
    try:
        address_counts = collections.Counter(int(m.get('Address', 0)) for m in methods)
        ready, details, discoveries, reasons = [], [], [], collections.Counter()
        for i, method in enumerate(methods):
            if i % 1024 == 0:
                check(cb, f'Проверка методов Rodroid: {i}/{rodroid_method_count}')
            address = int(method.get('Address', 0))
            signature = str(method.get('Signature', ''))
            dotnet = str(method.get('DotNetSignature') or method.get('Name') or '')
            group = str(method.get('Group') or '')
            method_name = dotnet.rsplit('::', 1)[-1].split('(', 1)[0]
            semantic = _semantic_tags(dotnet+' '+group)
            return_c = signature.split(None, 1)[0] if signature else ''
            kind = _RODROID_TYPES.get(return_c)
            params = signature.rsplit('(', 1)[-1].rsplit(')', 1)[0] if '(' in signature else ''
            real_params = [p.strip() for p in params.split(',') if p.strip() and 'MethodInfo' not in p]
            contract = _rodroid_signature_contract(signature)
            reason = None
            try:
                offset = e.offset(address, 4, True) if address > 0 else None
            except ValueError:
                offset = None
            if offset is None:
                reason = 'Нет положительного RVA в исполняемом сегменте'
            elif address_counts[address] != 1:
                reason = 'Общий адрес у нескольких методов'
            elif not kind:
                reason = 'Неподдерживаемый тип результата'
            elif len(real_params) > 1:
                reason = 'Метод принимает аргументы'
            elif not method_name.startswith(('get_', 'Get', 'Is', 'Has')):
                reason = 'Метод не распознан как получение значения'
            else:
                ix = bisect.bisect_right(addresses, address)
                span = addresses[ix] - address if ix < len(addresses) else 0
                if span < 8 or address % 4:
                    reason = 'Недостаточно данных о границе метода'
                else:
                    capacity = min(span, 24)
                    try:
                        e.offset(address, capacity, True)
                    except ValueError:
                        reason = 'Граница метода выходит за сегмент'
                    if reason is None:
                        ready.append(dict(id=i, label=dotnet, image=group.split('/', 1)[0],
                                          kind=kind, rva=address, offset=offset, capacity=capacity,
                                          original=e.b[offset:offset+capacity].hex(), source='rodroid-script.json',
                                          semantic=semantic, selectable=True, item_type='method', signature_contract=contract))
            # Keep the historical full report for normal/small analyses.  The
            # compact Android path only drops the enormous 100k+ Rodroid detail
            # array where it materially affects peak RSS.
            if not compact_return or rodroid_method_count <= 10000:
                details.append(dict(id=i, label=dotnet, signature=signature, group=group,
                                    rva=address if address > 0 else None, return_type=kind,
                                    signature_contract=contract, unavailable_reason=reason))
            if semantic and reason:
                discoveries.append(dict(id=i, label=dotnet, image=group.split('/', 1)[0],
                                        kind=kind or return_c or '?', rva=address if address > 0 else None,
                                        semantic=semantic, selectable=False, item_type='method',
                                        signature_contract=contract, unavailable_reason=reason))
            if reason:
                reasons[reason] += 1
        raw_dump = dump_path.read_text(encoding='utf-8', errors='replace')
        discoveries.extend(_dump_field_discoveries(raw_dump, rodroid_method_count))
        unresolved = len(__import__('re').findall(r'RVA:\s*(?:-1|0x0+)(?![0-9A-Fa-f])', raw_dump))
        rodroid_type_count = raw_dump.count('// TypeDefIndex:')
        script_resolved = sum(1 for m in methods if int(m.get('Address', 0)) > 0)
        if large_compact:
            # Spill the two remaining Rodroid result arrays before the metadata
            # resolver starts.  On large IL2CPP inputs this releases ~50k Python
            # dictionaries and prevents the 200+ MB catalogue finalizer from
            # running under avoidable heap pressure.
            initial_candidate_count = len(ready)
            initial_discovery_count = len(discoveries)
            ctmp, dtmp, utmp = str(candidate_file)+'.tmp', str(discovery_file)+'.tmp', str(ui_spool_file)+'.tmp'
            with open(ctmp, 'w', encoding='utf-8') as cf, open(dtmp, 'w', encoding='utf-8') as df, open(utmp, 'w', encoding='utf-8') as uf:
                for item in ready:
                    cf.write(json.dumps(item, ensure_ascii=False, separators=(',', ':'))+'\n')
                    uf.write(json.dumps(_analysis_ui_row(item), ensure_ascii=False, separators=(',', ':'))+'\n')
                for item in discoveries:
                    df.write(json.dumps(item, ensure_ascii=False, separators=(',', ':'))+'\n')
                    uf.write(json.dumps(_analysis_ui_row(item), ensure_ascii=False, separators=(',', ':'))+'\n')
            os.replace(ctmp, candidate_file); os.replace(dtmp, discovery_file); os.replace(utmp, ui_spool_file)
            ready.clear(); discoveries.clear()
        if compact_return:
            # Android/dev27 keeps the full metadata catalogue file-backed. Drop
            # the 300k+ Rodroid ScriptMethod object graph before metadata/ELF
            # correlation to avoid memory-pressure slowdowns and OOMs.
            script = None
            methods = None
            # These structures are Rodroid-only after the initial patch scan.
            # The standard metadata catalogue becomes the primary dev27 source.
            addresses = []
            address_counts = collections.Counter()
            if len(raw_dump) > 16 * 1024 * 1024:
                raw_dump = ''
            import gc as _gc
            _gc.collect()

        # Rodroid may leave a direct dump.cs declaration at RVA -1 even when the
        # standard IL2CPP module table can resolve the same metadata token. Resolve
        # those declarations conservatively: exact DLL + class + method + arity,
        # unique metadata key, unique native address, no collision with a Rodroid
        # ScriptMethod address. This is evidence-based fallback, not name guessing.
        metadata_resolved = []
        metadata_callable = []
        metadata_stats = {"available": False}
        metadata_observed_stats = {"available": False}
        metadata_catalog_stats = {"available": False}
        catalog_base_path = (str(method_catalog_path) + '.base') if method_catalog_path else None
        try:
            check(cb, 'Разрешение методов через global-metadata + CodeRegistration')
            # Dev27: for large Rodroid dumps the exact metadata catalogue already
            # supersedes textual RVA=-1 fallback. Avoid two additional regex
            # passes over tens of megabytes of dump.cs; keep legacy corroboration
            # for small fixtures/projects where it is cheap.
            parse_dump_declarations = len(raw_dump) <= 16 * 1024 * 1024
            unresolved_decls = list(_dump_unresolved_declarations(raw_dump)) if parse_dump_declarations else []
            wanted_meta_keys = {(d['image'], d['cls'], d['name'], d['args']) for d in unresolved_decls}
            meta_index, meta_addresses, meta_stats = _metadata_resolution_index(
                metadata_path, e, cb, wanted_keys=wanted_meta_keys, catalog_base_path=catalog_base_path)
            metadata_stats = {"available": True, **meta_stats}

            # Dev21 universal discovery pass: use the complete set of unique
            # CodeRegistration RVAs as native BL targets. This admits obfuscated
            # methods based on concrete native relations, not on method vocabulary.
            check(cb, 'Universal resolver: поиск BL-вызовов по всем metadata RVA')
            observed_counts, observed_first_refs, observed_scan = _arm64_direct_bl_observed_targets(
                e, meta_addresses, cb, max_scan_bytes=256 * 1024 * 1024, max_matches=250_000)
            observed_rvas = _select_observed_metadata_targets(observed_counts, max_rows=4096)
            observed_index = {}
            observed_materialize_stats = {}
            if observed_rvas:
                check(cb, 'Universal resolver: materialize вызванные metadata-методы')
                if catalog_base_path and Path(catalog_base_path).is_file():
                    observed_index, observed_materialize_stats = _materialize_observed_from_base_catalog(
                        metadata_path, e, catalog_base_path, observed_rvas, cb)
                else:
                    # Legacy/library callers may not request a file-backed catalog.
                    # Keep the old bounded second pass only for that small path; the
                    # production Android/dev27 path always reuses the base catalog.
                    observed_index, _ignored_addresses, observed_materialize_stats = _metadata_resolution_index(
                        metadata_path, e, cb, wanted_keys=(), wanted_rvas=observed_rvas,
                        include_generic_retention=False, catalog_base_path=None)
                for observed_key, observed_hit in observed_index.items():
                    meta_index.setdefault(observed_key, observed_hit)
            metadata_observed_stats = {
                'available': True, **observed_scan,
                'materializedTargets': len(observed_index),
                'materializationBudget': 4096,
                'materialization': observed_materialize_stats,
                'selection': ('all-observed' if len(observed_counts) <= 4096
                              else 'frequency+rare+address-spread'),
                'note': ('Direct BL evidence is structural only. It confirms a static native relation '
                         'to an exact unique CodeRegistration RVA, not runtime behaviour.'),
            }

            # dev12 method resolver: resolve *callable* semantic methods directly
            # from the metadata module table, independently of whether Rodroid put
            # them in ScriptMethod. This list is evidence for Menu Builder and is
            # deliberately separate from candidates used by the constant-return
            # binary patcher.
            # dump.cs is supplementary corroboration only.  The callable
            # inventory is driven directly by metadata rows + unique CodeRegistration
            # method pointers so a missing/partial Rodroid declaration cannot hide a
            # resolvable method.
            dump_groups = collections.defaultdict(list)
            if parse_dump_declarations:
                for decl in _dump_method_declarations(raw_dump):
                    dump_groups[(decl['image'], decl['cls'], decl['name'], decl['args'])].append(decl)
            dump_index = {k: v[0] for k, v in dump_groups.items() if len(v) == 1}

            callable_seen = set()
            callable_pool = []
            from modkit.reworkspace.method_evidence import build_method_verification, method_role
            for meta_key, hit in meta_index.items():
                row, addr = hit
                image, cls, name, argc = meta_key
                key = (image, cls, name, argc, addr)
                if key in callable_seen:
                    continue
                callable_seen.add(key)
                try:
                    call_off = e.offset(addr, 4, True)
                except ValueError:
                    continue
                decl = dump_index.get(meta_key)
                contract = _metadata_native_callable_contract(row, decl)
                label = cls + '::' + name
                semantic = _semantic_tags(label)
                # Dev21: retention is no longer gated by gameplay/debug
                # vocabulary. The metadata index already applied a generic,
                # bounded API-morphology policy after scanning the *entire*
                # metadata table for unique CodeRegistration mappings.
                role = method_role(label, contract)
                provenance = _il2cpp_provenance(image, cls)
                application_owned = provenance in {'game-primary', 'mixed-firstpass', 'custom-unknown'}
                priority = sum({
                    'cheat': 16, 'health': 9, 'damage': 9, 'money': 9,
                    'movement': 8, 'progression': 8, 'state': 6, 'inventory': 5,
                    'debug': 2,
                }.get(tag, 2) for tag in semantic)
                # Generic role score is deliberately independent of the target
                # application and keeps actionable Set/Enable/Toggle/Apply-style
                # APIs visible even when their nouns are unknown to our vocabulary.
                priority += {
                    'instance_resolver': 28, 'toggle_action': 18, 'setter': 16,
                    'action': 11, 'query': 1, 'unknown': 0,
                    'lifecycle': -35, 'generated': -30,
                }.get(role, 0)
                priority += {
                    'game-primary': 24,
                    'mixed-firstpass': 4,
                    'custom-unknown': 0,
                    'third-party-known': -20,
                    'framework': -28,
                }.get(provenance, -4)
                # Compiler/delegate glue stays searchable in the RE workspace,
                # but should never crowd the Menu Builder shortlist in large
                # large stripped IL2CPP projects.
                if name.casefold() in {'setstatemachine', 'movenext', 'begininvoke', 'endinvoke', 'invoke'}:
                    priority -= 40
                if '<' in cls or '>' in cls or '<' in name or '>' in name:
                    priority -= 18
                if contract.get('resolverSuggestion'):
                    priority += 20
                if contract.get('bindingSuggestion'):
                    priority += 7
                if contract.get('autoBindingSafe') and contract.get('isStatic'):
                    priority += 5
                if decl is not None:
                    priority += 2
                incoming_direct_bl = int(observed_counts.get(addr, 0))
                if incoming_direct_bl:
                    # A native edge to an exact metadata RVA is stronger retention
                    # evidence than any descriptive name. Keep rare obfuscated APIs
                    # visible as well as hot targets, while leaving semantics unknown.
                    priority += 34 + min(18, int(math.log2(incoming_direct_bl + 1) * 4))
                callable_row = dict(
                    id=0, label=label, image=image, kind=row.get('return_primitive') or 'managed',
                    rva=addr, offset=call_off, semantic=semantic, item_type='method', method_role=role,
                    source='global-metadata+CodeRegistration',
                    resolution='confirmed-unique-code-registration', selectable=False, callable=True,
                    signature_contract=contract, metadata_token=row.get('token'), metadata_method_id=row.get('id'),
                    dump_declaration=decl.get('declaration') if decl else None,
                    metadata_parameters=row.get('parameters', []), application_owned=application_owned,
                    provenance=provenance, _resolver_priority=priority,
                    static_incoming_direct_bl_count=incoming_direct_bl,
                    static_first_call_rva=((observed_first_refs.get(addr) or {}).get('callRva')
                                           if incoming_direct_bl else None),
                    discovery_reason=('exact-metadata-rva-observed-as-direct-bl-target'
                                      if incoming_direct_bl else 'generic-metadata-retention'),
                    unavailable_reason=(contract.get('bindingBlocker') if not contract.get('autoBindingSafe')
                                        and not contract.get('resolverSuggestion') else None),
                )
                callable_row['method_verification'] = build_method_verification(callable_row)
                callable_pool.append(callable_row)

            callable_pool.sort(key=lambda x: (-x['_resolver_priority'], x['label'].casefold(), x['rva']))
            # The report stays bounded for Android heap safety. All metadata
            # rows were scanned; this is the ranked detailed evidence window.
            metadata_callable = callable_pool[:4000]
            for i, item in enumerate(metadata_callable):
                item['id'] = rodroid_method_count + initial_discovery_count + len(discoveries) + i
                item.pop('_resolver_priority', None)

            fallback_id = rodroid_method_count + initial_discovery_count + len(discoveries) + len(metadata_callable)
            for decl in unresolved_decls:
                hit = meta_index.get((decl['image'], decl['cls'], decl['name'], decl['args']))
                if not hit:
                    continue
                row, addr = hit
                reason = None
                try:
                    off = e.offset(addr, 4, True)
                except ValueError:
                    off = None
                if off is None:
                    reason = 'Metadata RVA вне исполняемого сегмента'
                elif address_counts.get(addr, 0):
                    reason = 'Metadata RVA уже принадлежит Rodroid ScriptMethod'
                kind = _CSHARP_PRIMITIVES.get(decl['return_decl'])
                if reason is None and not kind:
                    reason = 'Metadata разрешила RVA, но тип результата не поддержан для патча'
                if reason is None and decl['args']:
                    reason = 'Metadata разрешила RVA, но метод принимает аргументы'
                if reason is None and not decl['name'].startswith(('get_', 'Get', 'Is', 'Has')):
                    reason = 'Metadata разрешила RVA, но метод не распознан как getter'
                capacity = 0
                if reason is None:
                    ix = bisect.bisect_right(meta_addresses, addr)
                    span = meta_addresses[ix] - addr if ix < len(meta_addresses) else 0
                    if span < 8 or addr % 4:
                        reason = 'Metadata разрешила RVA, но граница метода недостаточно надёжна'
                    else:
                        capacity = min(span, 24)
                        try:
                            e.offset(addr, capacity, True)
                        except ValueError:
                            reason = 'Metadata разрешила RVA, но граница выходит за сегмент'
                contract = (_metadata_native_callable_contract(row, decl)
                            if 'return_primitive' in row else _metadata_callable_contract(decl, row))
                entry = dict(id=fallback_id + len(metadata_resolved), label=decl['cls']+'::'+decl['name'],
                             image=decl['image'], kind=kind or decl['return_decl'], rva=addr, offset=off,
                             semantic=_semantic_tags(decl['cls']+' '+decl['name']), item_type='method',
                             source='global-metadata+CodeRegistration', resolution='confirmed-unique',
                             selectable=reason is None, signature_contract=contract, unavailable_reason=reason)
                metadata_resolved.append(entry)
                discoveries.append(entry.copy())
                if reason is None:
                    ready.append(dict(id=entry['id'], label=entry['label'], image=entry['image'], kind=kind,
                                      rva=addr, offset=off, capacity=capacity,
                                      original=e.b[off:off+capacity].hex(), source=entry['source'],
                                      semantic=entry['semantic'], selectable=True, item_type='method',
                                      signature_contract=contract, resolution=entry['resolution']))

            if method_catalog_path and catalog_base_path:
                check(cb, 'Universal resolver: финализация полного metadata-каталога')
                if large_compact and Path(catalog_base_path).is_file():
                    # Dev27 large-title fast path: the base catalogue is already
                    # the immutable complete identity/address inventory and its
                    # dense/page/RVA indices were written in the same streaming
                    # pass. Native relation/typed evidence lives in sidecars/Deep
                    # Resolver, so a second 200+ MB rewrite is both redundant and
                    # harmful under Android heap pressure.
                    os.replace(catalog_base_path, method_catalog_path)
                    for suffix in ('.idx', '.pages.idx', '.rva.idx'):
                        os.replace(str(catalog_base_path)+suffix, str(method_catalog_path)+suffix)
                    fc = metadata_stats.get('full_catalog') or {}
                    rows = int(fc.get('rows_written') or metadata_stats.get('metadata_methods') or 0)
                    address_confirmed = int(fc.get('address_confirmed') or 0)
                    typed_abi = sum(1 for x in metadata_callable if (x.get('signature_contract') or {}).get('shapeSupported'))
                    metadata_catalog_stats = {
                        'available': True, 'schema': 'modkit-full-metadata-method-catalog-1.0',
                        'file': Path(method_catalog_path).name, 'rows': rows,
                        'addressConfirmed': address_confirmed, 'mappingReview': max(0, rows-address_confirmed),
                        'directBlObserved': len(observed_counts),
                        'abiMaterialized': int(fc.get('abi_materialized') or 0),
                        'abiShapeSupported': int(fc.get('abi_shape_supported') or 0),
                        'typedWindow': len(metadata_callable), 'typedAbi': typed_abi,
                        'executableReady': sum(1 for x in metadata_callable if (x.get('method_verification') or {}).get('executableReady')),
                        'applicationOwned': int(fc.get('application_owned') or 0),
                        'generic': int(fc.get('generic') or 0), 'abstract': int(fc.get('abstract') or 0),
                        'storage': 'jsonl-file-backed', 'pageSize': 30, 'pageCount': (rows+29)//30,
                        'methodIdIndexFile': Path(str(method_catalog_path)+'.idx').name,
                        'methodIdIndexEncoding': 'big-endian-u64-byte-offset; UINT64_MAX=missing',
                        'rvaIndexFile': Path(str(method_catalog_path)+'.rva.idx').name,
                        'rvaIndexEncoding': 'sorted-big-endian-(u64-rva,u32-method-id)',
                        'pageIndexFile': Path(str(method_catalog_path)+'.pages.idx').name,
                        'runtimeTruth': 'not-observed-by-static-analysis',
                    }
                else:
                    metadata_catalog_stats = _finalize_metadata_method_catalog(
                        catalog_base_path, method_catalog_path, observed_counts, observed_first_refs,
                        metadata_callable, cb)
                # dev34: build a disk-backed exact-token search index after the
                # final JSONL path is stable. The index is only a candidate locator;
                # Android still evaluates the original JSON row before displaying it.
                try:
                    from modkit.mobile.metadata_catalog import build_method_search_index
                    search_stats = build_method_search_index(
                        method_catalog_path, poll=(lambda: check(cb)))
                    metadata_catalog_stats['searchIndex'] = search_stats
                    if search_stats.get('available'):
                        metadata_catalog_stats['searchIndexFile'] = search_stats.get('file')
                        metadata_catalog_stats['searchIndexEncoding'] = search_stats.get('encoding')
                        metadata_catalog_stats['searchIndexRecords'] = int(search_stats.get('records') or 0)
                        metadata_catalog_stats['searchTokenHashes'] = int(search_stats.get('tokenHashes') or 0)
                except Exception as search_exc:
                    metadata_catalog_stats['searchIndex'] = {
                        'available': False, 'error': str(search_exc),
                        'semantics': 'Optional UI acceleration only; catalogue evidence remains complete.',
                    }

                manifest_path = Path(method_catalog_path).with_name(Path(method_catalog_path).stem + '.meta.json')
                manifest_temp = str(manifest_path) + '.tmp'
                Path(manifest_temp).write_text(
                    json.dumps(metadata_catalog_stats, ensure_ascii=False, separators=(',', ':')),
                    encoding='utf-8')
                os.replace(manifest_temp, manifest_path)
                metadata_catalog_stats['manifest'] = manifest_path.name
        except Exception as exc:
            metadata_stats = {"available": False, "error": str(exc)}
            metadata_catalog_stats = {"available": False, "error": str(exc)}
            if catalog_base_path:
                try:
                    Path(catalog_base_path).unlink()
                except FileNotFoundError:
                    pass

        with open(metadata_path, 'rb') as f:
            head = f.read(8)
        metadata_version = struct.unpack('<II', head)[1] if len(head) == 8 and struct.unpack('<I', head[:4])[0] == 0xFAB11BAF else 0
        result = dict(schema=3, engine='Rodroid Il2CppDumper', engine_version='0.7.0',
                      engine_commit='8bfb90229539833999e725c5cf6402a435b47f15',
                      source_of_truth=['dump.cs', 'script.json', 'global-metadata+CodeRegistration'], metadata_version=metadata_version,
                      types=rodroid_type_count, methods=rodroid_method_count,
                      resolved=script_resolved+len(metadata_resolved), resolved_script=script_resolved,
                      resolved_metadata=len(metadata_resolved), unresolved=max(0, unresolved-len(metadata_resolved)),
                      metadata_resolution=metadata_stats, metadata_resolved_methods=metadata_resolved,
                      metadata_observed_call_resolution=metadata_observed_stats,
                      metadata_method_catalog=metadata_catalog_stats,
                      metadata_callable_resolution=dict(available=metadata_stats.get('available', False),
                          resolved=len(metadata_callable), executable_contracts=sum(1 for x in metadata_callable if (x.get('signature_contract') or {}).get('autoBindingSafe')),
                          structurally_ready=sum(1 for x in metadata_callable if (x.get('method_verification') or {}).get('executableReady')),
                          direct_bl_observed=sum(1 for x in metadata_callable if x.get('static_incoming_direct_bl_count')),
                          instance_resolvers=sum(1 for x in metadata_callable if (x.get('signature_contract') or {}).get('resolverSuggestion')),
                          retention_policy='full-file-backed-metadata-catalog+bounded-typed-abi+all-RVA-direct-BL; no app-specific gate'),
                      metadata_callable_methods=metadata_callable,
                      modules=(int(metadata_stats.get('modules') or 0) if metadata_stats.get('available') else len({d['group'].split('/', 1)[0] for d in details if d.get('group')})),
                      type_table_found=True, candidates=ready, method_details=details,
                      discoveries=discoveries,
                      semantic_categories={k: sorted(v) for k, v in _SEMANTIC_WORDS.items()},
                      deobfuscation=dict(mode='semantic-heuristic',
                          note='Смысл восстанавливается по контексту класса, сигнатуре и связанным именам; зашифрованные имена без контекста нельзя достоверно восстановить.'),
                      unavailable=dict(reasons), metadata_sha256=digest(metadata_path, cb),
                      library_sha256=digest(library_path, cb),
                      dump_files=sorted(p.name for p in dump_dir.iterdir() if p.is_file()),
                      warning='Положительные RVA Rodroid остаются источником для patch-кандидатов. Universal Method Resolver сканирует всю metadata для проверки CodeRegistration, сохраняет каждый metadata-метод в отдельном file-backed каталоге, ищет ARM64 direct-BL по всему множеству уникальных metadata RVA (включая обфусцированные имена), а typed ABI материализует отдельно и ограниченно без привязки к тестовым приложениям; structural/ABI/semantic/runtime уровни доказательств не смешиваются. Неоднозначные адреса и неподдержанные сигнатуры остаются review-only.')
        check(cb, f'Rodroid-анализ завершён: {initial_candidate_count + len(ready)} доступных методов')
        # Dev27: on Android / very large IL2CPP applications ``analysis.json`` is a
        # compact manifest, not a second copy of every catalogue row.  Patchable
        # Rodroid candidates are stored in a tiny file-backed JSONL sidecar so the
        # legacy export path can still resolve an exact selection by id.  The full
        # metadata inventory, relationship graph and deep results live in their
        # dedicated file-backed artefacts.  Small/desktop analyses intentionally
        # retain the historical monolithic report for compatibility.
        compact_manifest = large_compact
        if compact_manifest:
            # Any late metadata fallback candidates are appended to the same
            # sidecar. Normal large-title flow has none because dump.cs textual
            # fallback is intentionally skipped, but keeping this makes the
            # storage contract complete.
            if ready:
                with candidate_file.open('a', encoding='utf-8') as candidate_out:
                    for item in ready:
                        candidate_out.write(json.dumps(item, ensure_ascii=False, separators=(',', ':'))+'\n')
            if discoveries:
                with discovery_file.open('a', encoding='utf-8') as discovery_out:
                    for item in discoveries:
                        discovery_out.write(json.dumps(item, ensure_ascii=False, separators=(',', ':'))+'\n')
            report_result = dict(
                schema=result['schema'], engine=result['engine'], engine_version=result['engine_version'],
                engine_commit=result['engine_commit'], source_of_truth=result['source_of_truth'],
                metadata_version=result['metadata_version'], types=result['types'], methods=result['methods'],
                resolved=result['resolved'], resolved_script=result['resolved_script'],
                resolved_metadata=result['resolved_metadata'], unresolved=result['unresolved'],
                metadata_resolution=result['metadata_resolution'],
                metadata_observed_call_resolution=result['metadata_observed_call_resolution'],
                metadata_method_catalog=result['metadata_method_catalog'],
                metadata_callable_resolution=result['metadata_callable_resolution'],
                modules=result['modules'], type_table_found=result['type_table_found'],
                candidate_count=initial_candidate_count + len(ready), discovery_count=initial_discovery_count + len(discoveries),
                metadata_callable_count=len(metadata_callable),
                candidate_file=candidate_file.name, discovery_file=discovery_file.name,
                method_catalog_file=(Path(method_catalog_path).name if method_catalog_path and Path(method_catalog_path).is_file() else None),
                ui_index_file=(Path(ui_index_path).name if ui_index_path else None),
                semantic_categories=result['semantic_categories'], deobfuscation=result['deobfuscation'],
                unavailable=result['unavailable'], metadata_sha256=result['metadata_sha256'],
                library_sha256=result['library_sha256'], dump_files=result['dump_files'], warning=result['warning'],
                storage=dict(mode='file-backed',
                    note='analysis.json is a compact manifest; full methods/relations/evidence are stored in sidecar catalogues',
                    candidates=candidate_file.name, discoveries=discovery_file.name,
                    methods=(Path(method_catalog_path).name if method_catalog_path else None)),
            )
        else:
            report_result = result
        temp = str(output_path)+'.tmp'
        with open(temp, 'w', encoding='utf-8') as report_file:
            json.dump(report_result, report_file, ensure_ascii=False, separators=(',', ':'))
        os.replace(temp, output_path)

        if compact_return:
            # Android keeps only this small summary in its Java heap. The complete
            # candidate/discovery catalogue remains file-backed and is scanned a
            # page at a time by MainActivity. This also makes process restoration
            # cheap: analysis.summary.json never contains the 28k+ row catalogue.
            if ui_index_path:
                import shutil
                ui_temp = str(ui_index_path)+'.tmp'
                with open(ui_temp, 'wb') as ui_raw:
                    if large_compact and ui_spool_file.is_file():
                        with ui_spool_file.open('rb') as pre:
                            shutil.copyfileobj(pre, ui_raw, length=1024*1024)
                # Append only the small post-metadata window. Large Rodroid rows
                # were projected once while spilling, so they are never reparsed.
                with open(ui_temp, 'a', encoding='utf-8') as ui_file:
                    seen = set()
                    for item in ready + metadata_callable + discoveries:
                        identity = (item.get('id'), item.get('label'), item.get('rva'), bool(item.get('selectable', True)))
                        if identity in seen:
                            continue
                        seen.add(identity)
                        ui_file.write(json.dumps(_analysis_ui_row(item), ensure_ascii=False, separators=(',', ':'))+'\n')
                os.replace(ui_temp, ui_index_path)
                if large_compact:
                    try: ui_spool_file.unlink()
                    except FileNotFoundError: pass
            compact = dict(
                schema=result['schema'], engine=result['engine'], engine_version=result['engine_version'],
                metadata_version=result['metadata_version'], types=result['types'], methods=result['methods'],
                resolved=result['resolved'], resolved_script=result['resolved_script'],
                resolved_metadata=result['resolved_metadata'], unresolved=result['unresolved'],
                modules=result['modules'], type_table_found=result['type_table_found'],
                candidate_count=initial_candidate_count + len(ready), discovery_count=initial_discovery_count + len(discoveries),
                metadata_callable_count=len(metadata_callable),
                metadata_callable_resolution=result['metadata_callable_resolution'],
                metadata_observed_call_resolution=result['metadata_observed_call_resolution'],
                metadata_method_catalog=result['metadata_method_catalog'],
                method_catalog_file=(Path(method_catalog_path).name if method_catalog_path and Path(method_catalog_path).is_file() else None),
                semantic_categories=result['semantic_categories'], unavailable=result['unavailable'],
                metadata_sha256=result['metadata_sha256'], library_sha256=result['library_sha256'],
                dump_files=result['dump_files'], warning=result['warning'],
                ui_index_file=(Path(ui_index_path).name if ui_index_path else None),
                candidate_file=(candidate_file.name if compact_manifest else None),
                discovery_file=(discovery_file.name if compact_manifest else None),
                report_storage=('file-backed-manifest' if compact_manifest else 'inline-legacy'),
            )
            return json.dumps(compact, ensure_ascii=False, separators=(',', ':'))

        # Desktop/tests keep the historical return shape for compatibility. The
        # full method_details table is still available in output_path.
        return json.dumps({k:v for k,v in result.items() if k != 'method_details'}, ensure_ascii=False)
    finally:
        e.close()


def patch_bytes(kind, value):
    if kind == 'bool':
        if str(value).lower() not in ('0', '1', 'true', 'false'):
            raise ValueError('Для bool допустимы только 0 или 1')
        return mov_imm(value=int(str(value).lower() in ('1', 'true')), wide=False) + ret()
    if kind in ('float', 'double'):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('Нужно конечное число')
        if kind == 'float':
            bits = struct.unpack('<I', struct.pack('<f', number))[0]
            return mov_imm(value=bits, wide=False) + struct.pack('<I', 0x1E270000) + ret()
        bits = struct.unpack('<Q', struct.pack('<d', number))[0]
        return mov_imm(value=bits) + struct.pack('<I', 0x9E670000) + ret()
    if kind not in ('int8','uint8','int16','uint16','int32','uint32','int64','uint64'):
        raise ValueError('Неподдерживаемый тип результата')
    number = int(str(value), 10)
    unsigned = kind.startswith('u')
    width = int(kind[4:] if unsigned else kind[3:])
    low, high = (0, (1 << width)-1) if unsigned else (-(1 << (width-1)), (1 << (width-1))-1)
    if not low <= number <= high:
        raise ValueError(f'Число вне диапазона {kind}: {low} … {high}')
    return mov_imm(value=number, wide=width == 64) + ret()


def build_gameplay_discovery(metadata_path, library_path, catalog_path, graph_path, coverage_path, apk_path=None, analysis_manifest_path=None, cb=None):
    """Dev27 shared Evidence Graph -> user-facing gameplay coverage pipeline."""
    from modkit.mobile.gameplay import build_evidence_graph, build_gameplay_coverage, scan_apk_package_evidence
    check(cb, 'Gameplay Discovery: Evidence Graph…')
    manifest = build_evidence_graph(metadata_path, library_path, catalog_path, graph_path, cb)
    check(cb, 'Gameplay Discovery: package/content evidence…')
    package = scan_apk_package_evidence(apk_path) if apk_path and Path(apk_path).is_file() else []
    check(cb, 'Gameplay Discovery: coverage summary…')
    coverage = build_gameplay_coverage(graph_path, package_evidence=package, output_path=coverage_path)
    compact_cards=[]
    for card in coverage.get('cards') or []:
        fields=[f"{x.get('declaringType')}.{x.get('name')} @ 0x{int(x.get('runtimeOffset') or 0):x}" for x in (card.get('fields') or [])[:4]]
        methods=[str(x.get('label') or '') for x in (card.get('methods') or [])[:5] if x.get('label')]
        compact_cards.append({
            'domain':card.get('domain'),'title':card.get('title'),'status':card.get('status'),
            'fields':fields,'methods':methods,'packageCount':len(card.get('package') or []),
            **({'numericHpSetterAttributed':bool(card.get('numericHpSetterAttributed'))} if card.get('domain')=='health' else {}),
        })
    compact={
        'schema':'modkit-gameplay-discovery-1.0','graph':manifest,'cards':compact_cards,
        'coverageFile':Path(coverage_path).name,'packageEvidenceCount':len(package),
        'note':coverage.get('note'),'runtimeTruth':'not-observed-by-static-analysis',
    }
    if analysis_manifest_path and Path(analysis_manifest_path).is_file():
        try:
            report=json.loads(Path(analysis_manifest_path).read_text(encoding='utf-8'))
            report['gameplayDiscovery']=compact
            tmp=str(analysis_manifest_path)+'.tmp'
            Path(tmp).write_text(json.dumps(report,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
            os.replace(tmp,analysis_manifest_path)
        except (OSError,ValueError):
            pass
    return json.dumps(compact, ensure_ascii=False, separators=(',', ':'))


def _patch_candidates_from_report(report_path, report):
    """Return patchable Rodroid rows from inline legacy report or dev27 sidecar."""
    rows = report.get('candidates')
    if isinstance(rows, list):
        return rows
    name = report.get('candidate_file')
    if not name:
        return []
    path = Path(report_path).with_name(Path(name).name)
    if not path.is_file():
        raise ValueError('Файл patch-кандидатов отсутствует. Запустите анализ заново.')
    out=[]
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def export(report_path, library_path, selections_json, output_zip, cb=None):
    report = json.loads(Path(report_path).read_text(encoding='utf-8'))
    selections = json.loads(selections_json)
    if not selections:
        raise ValueError('Выберите хотя бы одно изменение')
    check(cb, 'Проверка исходной библиотеки')
    if digest(library_path, cb) != report['library_sha256']:
        raise ValueError('Библиотека изменилась после анализа. Запустите анализ заново.')
    candidates = {c['id']: c for c in _patch_candidates_from_report(report_path, report)}
    patches = []
    seen = set()
    for s in selections:
        if s['id'] in seen or s['id'] not in candidates:
            raise ValueError('Недопустимый или повторный метод')
        seen.add(s['id'])
        c = candidates[s['id']]
        patch = patch_bytes(c['kind'], s['value'])
        original = bytes.fromhex(c['original'])
        if len(original) >= 4 and struct.unpack_from('<I', original)[0] in (0xd503245f, 0xd503249f, 0xd50324df):
            patch = original[:4] + patch  # Preserve ARM branch target identification landing pad.
        if len(patch) > c['capacity']:
            raise ValueError(c['label']+': выбранное число требует больше места, чем доступно в методе')
        patches.append({**c, 'value':s['value'], 'patch':patch.hex()})
    patches.sort(key=lambda p:p['offset'])
    for a,b in zip(patches, patches[1:]):
        if a['offset'] + len(bytes.fromhex(a['patch'])) > b['offset']:
            raise ValueError('Изменения пересекаются')
    size = os.path.getsize(library_path)
    with open(library_path, 'rb') as f:
        for p in patches:
            old = bytes.fromhex(p['original'])
            if p['offset'] < 0 or p['offset'] + len(old) > size:
                raise ValueError('Некорректные границы патча')
            f.seek(p['offset'])
            if f.read(len(old)) != old:
                raise ValueError('Исходные байты не совпадают с анализом')
    temp = str(output_zip) + '.tmp'
    try:
        h = hashlib.sha256()
        with zipfile.ZipFile(temp, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as z, open(library_path, 'rb') as src:
            with z.open('libil2cpp.so', 'w', force_zip64=True) as dst:
                position = 0
                def copy_until(end):
                    nonlocal position
                    while position < end:
                        check(cb, f'Создание библиотеки: {position * 100 // max(size,1)}%')
                        chunk = src.read(min(1024*1024, end-position))
                        if not chunk:
                            raise ValueError('Неожиданный конец библиотеки')
                        dst.write(chunk)
                        h.update(chunk)
                        position += len(chunk)
                for p in patches:
                    copy_until(p['offset'])
                    data = bytes.fromhex(p['patch'])
                    dst.write(data)
                    h.update(data)
                    src.seek(len(data), 1)
                    position += len(data)
                copy_until(size)
            receipt = dict(source_sha256=report['library_sha256'], result_sha256=h.hexdigest(),
                           metadata_sha256=report['metadata_sha256'], changes=patches,
                           verified='Файловые границы и исходные байты проверены; в игре не проверено')
            z.writestr('changes.json', json.dumps(receipt, ensure_ascii=False, indent=2))
            z.write(report_path, 'analysis.json')
            dump_dir = Path(report_path).parent / 'rodroid' / 'Dump0'
            for name in ('dump.cs','script.json','stringliteral.json','generics_dump.txt','static_metadata.json','il2cpp.h'):
                artifact = dump_dir / name
                if artifact.is_file():
                    z.write(artifact, 'rodroid/'+name)
            z.writestr('README-RU.txt', 'Результат ModKit\n\nlibil2cpp.so — изменённая копия выбранной библиотеки ARM64.\n'
                       'changes.json — изменения, исходные байты для отката и SHA-256.\n'
                       'analysis.json — результаты анализа.\n\n'
                       'Это не установочный APK и не плавающее меню. Изменения постоянны в этой копии.\n'
                       'Оригинальные выбранные файлы не изменены. Для сборки APK нужны остальные файлы приложения и подпись.\n'
                       'Каждый выбранный метод возвращает указанную константу вместо выполнения исходного тела. '
                       'Побочные действия исходного метода также пропускаются. Проверяйте копию приложения.\n')
        check(cb)
        os.replace(temp, output_zip)
        return json.dumps(receipt, ensure_ascii=False)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _aligned_extra(output_zip, filename, alignment):
    position = output_zip.fp.tell()
    base = position + 30 + len(filename.encode('utf-8'))
    padding = (-base) % alignment
    if padding and padding < 4:
        padding += alignment
    return b'' if not padding else struct.pack('<HH', 0xCAFE, padding-4) + bytes(padding-4)


def export_apk_unsigned(report_path, library_path, selections_json, source_apk, output_apk, cb=None):
    """Rebuild an unsigned APK with the patched arm64-v8a IL2CPP library."""
    temp_mod = str(output_apk) + '.mod.zip'
    patched_library = str(output_apk) + '.libil2cpp.so'
    temp_apk = str(output_apk) + '.tmp'
    try:
        export(report_path, library_path, selections_json, temp_mod, cb)
        with zipfile.ZipFile(temp_mod) as mod, mod.open('libil2cpp.so') as src, open(patched_library, 'wb') as dst:
            while chunk := src.read(1024*1024):
                check(cb, 'Подготовка изменённой библиотеки')
                dst.write(chunk)
        target = 'lib/arm64-v8a/libil2cpp.so'
        with zipfile.ZipFile(source_apk, 'r') as source:
            try:
                original_info = source.getinfo(target)
            except KeyError:
                raise ValueError('В исходном APK нет lib/arm64-v8a/libil2cpp.so')
            h = hashlib.sha256()
            with source.open(original_info) as entry:
                while chunk := entry.read(1024*1024):
                    check(cb, 'Проверка библиотеки внутри APK')
                    h.update(chunk)
            report = json.loads(Path(report_path).read_text(encoding='utf-8'))
            if h.hexdigest() != report['library_sha256']:
                raise ValueError('Выбранная libil2cpp.so не совпадает с ARM64-библиотекой исходного APK')
            with zipfile.ZipFile(temp_apk, 'w', allowZip64=True) as output:
                entries = source.infolist()
                for index, info in enumerate(entries):
                    check(cb, f'Сборка APK: {index*100//max(1,len(entries))}%')
                    upper = info.filename.upper()
                    if upper.startswith('META-INF/') and upper.endswith(('.RSA','.DSA','.EC','.SF','/MANIFEST.MF')):
                        continue
                    zi = copy.copy(info)
                    zi.extra = b''
                    zi.flag_bits &= ~0x08
                    if info.filename == target:
                        zi.file_size = zi.compress_size = os.path.getsize(patched_library)
                        zi.CRC = 0
                        zi.compress_type = zipfile.ZIP_STORED
                        zi.extra = _aligned_extra(output, zi.filename, 16384)
                        with output.open(zi, 'w', force_zip64=True) as dst, open(patched_library, 'rb') as src:
                            while chunk := src.read(1024*1024):
                                check(cb)
                                dst.write(chunk)
                    else:
                        if zi.compress_type == zipfile.ZIP_STORED:
                            alignment = 16384 if zi.filename.endswith('.so') else 4
                            zi.extra = _aligned_extra(output, zi.filename, alignment)
                        with source.open(info) as src, output.open(zi, 'w', force_zip64=info.file_size >= 0xffffffff) as dst:
                            while chunk := src.read(1024*1024):
                                check(cb)
                                dst.write(chunk)
                receipt = json.loads(zipfile.ZipFile(temp_mod).read('changes.json'))
                receipt.update(dict(source_apk_sha256=digest(source_apk, cb), signature='unsigned; Android layer signs after alignment'))
                data = json.dumps(receipt, ensure_ascii=False, indent=2).encode('utf-8')
                zi = zipfile.ZipInfo('assets/modkit-build-receipt.json')
                zi.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(zi, data)
        os.replace(temp_apk, output_apk)
        return json.dumps(dict(apk_sha256=digest(output_apk, cb), replaced_entry=target), ensure_ascii=False)
    finally:
        for path in (temp_mod, patched_library, temp_apk):
            if os.path.exists(path):
                os.unlink(path)


def export_dump(rodroid_root, report_path, output_zip, cb=None, catalog_path=None, catalog_manifest_path=None, deep_dir=None):
    """Export Rodroid artifacts plus the optional full ModKit metadata catalogue."""
    root = Path(rodroid_root)
    report = Path(report_path)
    if not root.is_dir() or not report.is_file():
        raise ValueError('Сначала выполните полный анализ Rodroid')
    files = sorted(p for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    required = {p.name for p in files}
    if not {'dump.cs', 'script.json'} <= required:
        raise ValueError('Дамп неполный: отсутствует dump.cs или script.json')
    manifest = {
        'schema': 1,
        'engine': 'Rodroid Il2CppDumper 0.7.0',
        'engine_commit': '8bfb90229539833999e725c5cf6402a435b47f15',
        'files': [],
    }
    temp = str(output_zip)+'.tmp'
    try:
        with zipfile.ZipFile(temp, 'w', zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as z:
            for index, path in enumerate(files):
                check(cb, f'Упаковка дампа: {index+1}/{len(files)} — {path.name}')
                relative = path.relative_to(root).as_posix()
                manifest['files'].append({'path':'rodroid/'+relative,
                                          'size':path.stat().st_size,
                                          'sha256':digest(path, cb)})
                z.write(path, 'rodroid/'+relative)
            manifest['files'].append({'path':'analysis.json','size':report.stat().st_size,
                                      'sha256':digest(report, cb)})
            z.write(report, 'analysis.json')
            extras = []
            if catalog_path and Path(catalog_path).is_file():
                catalog_file = Path(catalog_path)
                extras.append(('analysis.methods.jsonl', catalog_file))
                method_index = Path(str(catalog_file) + '.idx')
                if method_index.is_file():
                    extras.append(('analysis.methods.jsonl.idx', method_index))
                page_index = Path(str(catalog_file) + '.pages.idx')
                if page_index.is_file():
                    extras.append(('analysis.methods.jsonl.pages.idx', page_index))
                rva_index = Path(str(catalog_file) + '.rva.idx')
                if rva_index.is_file():
                    extras.append(('analysis.methods.jsonl.rva.idx', rva_index))
                search_index = Path(str(catalog_file) + '.search.idx')
                if search_index.is_file():
                    extras.append(('analysis.methods.jsonl.search.idx', search_index))
                for archive_name in (
                    'analysis.evidence-graph.jsonl', 'analysis.evidence-graph.jsonl.idx',
                    'analysis.evidence-graph.meta.json', 'analysis.fields.jsonl',
                    'analysis.resolver-index.json', 'analysis.autopilot-index.jsonl',
                    'analysis.gameplay-coverage.json',
                ):
                    sidecar = catalog_file.with_name(archive_name)
                    if sidecar.is_file():
                        extras.append((archive_name, sidecar))
            if catalog_manifest_path and Path(catalog_manifest_path).is_file():
                extras.append(('analysis.methods.meta.json', Path(catalog_manifest_path)))
            if deep_dir and Path(deep_dir).is_dir():
                for deep_file in sorted(Path(deep_dir).glob('method-*.json')):
                    if deep_file.is_file() and not deep_file.is_symlink():
                        extras.append(('analysis-deep/' + deep_file.name, deep_file))
            for archive_name, path in extras:
                check(cb, 'Упаковка универсального metadata-каталога — ' + archive_name)
                manifest['files'].append({'path':archive_name,'size':path.stat().st_size,
                                          'sha256':digest(path, cb)})
                z.write(path, archive_name)
            z.writestr('dump-manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
            z.writestr('README-RU.txt', 'Полный дамп Rodroid Il2CppDumper 0.7.0 + ModKit Universal Resolver.\n\n'
                       'rodroid/ — все файлы, созданные движком.\n'
                       'analysis.json — результаты ModKit на основе dump.cs/script.json.\n'
                       'analysis.methods.jsonl — полный file-backed каталог всех metadata-методов, если он был создан.\n'
                       'analysis.methods.jsonl.idx — dense metadataMethodId→byteOffset индекс.\n'
                       'analysis.methods.jsonl.pages.idx — byte-offset индекс страниц полного каталога.\n'
                       'analysis.methods.jsonl.rva.idx — sorted RVA→metadataMethodId индекс.\n'
                       'analysis.methods.jsonl.search.idx — disk-backed token→metadataMethodId индекс для быстрого поиска.\n'
                       'analysis.methods.meta.json — сводка полного каталога.\n'
                       'analysis.evidence-graph.jsonl — callers/callees, exact typed fields и semantic graph.\n'
                       'analysis.fields.jsonl — exact FieldDefinition→runtime offset каталог.\n'
                       'analysis.resolver-index.json — type-exact instance resolver candidates.\n'
                       'analysis.autopilot-index.jsonl — компактная очередь discovery/ranking.\n'
                       'analysis.gameplay-coverage.json — HP/Damage/Currency/Level/Speed/Resources и другие игровые сущности.\n'
                       'analysis-deep/ — on-demand доказательства Deep Resolver для проверенных методов.\n'
                       'dump-manifest.json — размеры и SHA-256 каждого файла.\n')
        check(cb)
        os.replace(temp, output_zip)
        return json.dumps({'files':len(manifest['files']), 'sha256':digest(output_zip, cb)}, ensure_ascii=False)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

# ---------------------------------------------------------------------------
# 0.9 RE / Native Workspace / Patch Pack bridge


def _atomic_stream_json(path, payload, cb=None, stage_prefix=None):
    """Write JSON without constructing a second full-size string in memory.

    The destination is replaced only after a complete write.  This matters on
    Android where a large RE report can be hundreds of megabytes: ``json.dumps``
    would temporarily duplicate the report and can push the process over the
    heap/RSS limit exactly at the final save stage.
    """
    path = str(path)
    temp = path + ".tmp"
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    written_chars = 0
    next_progress = 8 * 1024 * 1024
    try:
        with open(temp, "w", encoding="utf-8") as fh:
            for chunk in encoder.iterencode(payload):
                fh.write(chunk)
                written_chars += len(chunk)
                if written_chars >= next_progress:
                    if stage_prefix:
                        check(cb, f"{stage_prefix} {written_chars // (1024 * 1024)} МБ…")
                    else:
                        check(cb)
                    next_progress += 8 * 1024 * 1024
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        raise


def _re_ui_snapshot(result, report_state="saving", report_size_bytes=None):
    """Build a bounded projection for the Android RE Workspace screen.

    The full ``re-analysis.json`` remains authoritative and is not pruned.  The
    Android activity must never parse that full report merely to render a few
    counters/cards, because org.json materializes the whole tree on the Java heap.
    """
    def clip(value, limit=1200):
        text = "" if value is None else str(value)
        return text if len(text) <= limit else text[:limit - 1] + "…"

    def as_int(value, default=0):
        try:
            if isinstance(value, str):
                return int(value, 0)
            return int(value)
        except (TypeError, ValueError):
            return default

    inv = result.get("inventory") or {}
    rel = result.get("nativeRelations") or {}
    graph = result.get("relationshipGraph") or {}
    gs = graph.get("summary") or {}
    sem = result.get("semanticVerification") or {}
    ctx = result.get("methodContextVerification") or {}
    method_verify = result.get("methodVerification") or {}
    mctx = rel.get("il2cppMethodContextSummary") or {}
    candidates = result.get("controlCandidates") or []
    findings = result.get("findings") or []
    inputs = result.get("inputSources") or {}
    diag = result.get("pipelineDiagnostics") or {}

    def count(name):
        rows = rel.get(name) or []
        return len(rows) if isinstance(rows, list) else 0

    summary_text = (
        f"DEX: {len(inv.get('dex') or [])} · native: {len(inv.get('native') or [])}"
        f" · DEX→SO: {count('dexNativeLinks')} · SO→SO refs: {count('embeddedLibraryStringEdges')}"
        f" · symbols: {count('symbolEdges')}/{count('dynamicSymbolEdges')}"
        f" · DT_NEEDED: {count('dependencyEdges')} · JNI: {count('jniSurfaces')}"
        f" · JNI refs: {count('jniDirectCallRefs')} · IL2CPP xrefs: {count('il2cppDirectCallRefs')}"
        f" · semantic: {as_int(sem.get('verified'))} verified / {as_int(sem.get('correlatedReview'))} correlated / {as_int(sem.get('review'))} review"
        f" · context: {as_int(ctx.get('verified'))} verified / {as_int(ctx.get('correlatedReview'))} correlated / {as_int(ctx.get('review'))} review"
        f" · method proof: {as_int(method_verify.get('addressConfirmed'))} address / {as_int(method_verify.get('abiConfirmed'))} ABI / {as_int(method_verify.get('xrefCorroborated'))} xref"
        f" · method ctx: {as_int(mctx.get('methods'))} methods / {as_int(mctx.get('outgoingManagedCalls'))} calls / {as_int(mctx.get('stringRefs'))} strings / {as_int(mctx.get('thisOffsetCandidates'))} offsets"
        f" · graph: {as_int(gs.get('nodes'))}n/{as_int(gs.get('edges'))}e"
        f" · chains: {as_int(gs.get('completeChains'))} + native {as_int(gs.get('nativeOnlyChains'))} · gaps: {as_int(gs.get('unlinkedControls'))}"
        f" · dlopen/dlsym: {count('dynamicLoadingSurfaces')} · render/input: {count('renderInputSurfaces')}"
        f" · находок: {len(findings)} · control candidates: {len(candidates)}"
    )
    if inputs:
        summary_text += (
            "\nIL2CPP input: " + clip(inputs.get("mode", "unknown"), 160)
            + " · metadata " + clip(inputs.get("metadata", "—"), 160)
            + " · library " + clip(inputs.get("library", "—"), 160)
            + " · Rodroid " + ("loaded" if inputs.get("il2cppReportLoaded") else "missing")
        )
    if diag:
        summary_text += (
            "\nPipeline: " + clip(diag.get("managedXrefStatus", "unknown"), 120)
            + " · IL2CPP rows " + str(as_int(diag.get("il2cppRows")))
            + " · external library " + ("YES" if diag.get("externalLibraryUsed") else "NO")
        )

    control_lines = []
    for item in candidates[:20]:
        if not isinstance(item, dict):
            continue
        line = ("VERIFIED" if item.get("semanticVerified") else "REVIEW") + " · " + clip(item.get("title"), 320)
        if item.get("evidenceRva") is not None:
            line += f" · RVA 0x{as_int(item.get('evidenceRva')):x}"
        if item.get("provenance"):
            line += " · " + clip(item.get("provenance"), 220)
        if item.get("gameplayRelevance") is not None:
            line += " · relevance " + str(as_int(item.get("gameplayRelevance")))
        blocker = item.get("contextBlocker") or item.get("bindingBlocker")
        if blocker:
            line += " · " + clip(blocker, 300)
        control_lines.append(clip(line))

    # Only resolve labels for nodes which can actually be displayed.  Copying
    # every graph node into another dict here would recreate the same peak-RSS
    # problem this projection is intended to avoid.
    complete_chains = (graph.get("completeChains") or [])[:8]
    native_chains = (graph.get("nativeOnlyChains") or [])[:8]
    partial_chains = (graph.get("partialLoaderChains") or [])[:8]
    wanted_node_ids = set()
    for chain in list(complete_chains) + list(native_chains) + list(partial_chains):
        if isinstance(chain, dict):
            wanted_node_ids.update(str(x) for x in (chain.get("nodes") or [])[:16])
    node_labels = {}
    for node in graph.get("nodes") or []:
        if isinstance(node, dict):
            node_id = str(node.get("id", ""))
            if node_id in wanted_node_ids:
                node_labels[node_id] = clip(node.get("label") or node_id, 260)
                if len(node_labels) >= len(wanted_node_ids):
                    break

    graph_lines = []
    for chain in complete_chains:
        if not isinstance(chain, dict):
            continue
        labels = [node_labels.get(str(x), clip(x, 260)) for x in (chain.get("nodes") or [])[:16]]
        graph_lines.append(clip("CHAIN · " + " → ".join(labels) + f" · confidence {float(chain.get('confidence') or 0):.2f}"))
    for chain in native_chains:
        if not isinstance(chain, dict):
            continue
        labels = [node_labels.get(str(x), clip(x, 260)) for x in (chain.get("nodes") or [])[:16]]
        graph_lines.append(clip("NATIVE CHAIN · " + " → ".join(labels) + f" · confidence {float(chain.get('confidence') or 0):.2f}"))
    for chain in partial_chains:
        if not isinstance(chain, dict):
            continue
        labels = [node_labels.get(str(x), clip(x, 260)) for x in (chain.get("nodes") or [])[:16]]
        graph_lines.append(clip("PARTIAL · " + " → ".join(labels) + " · static chain ends here"))
    for gap in (graph.get("gaps") or [])[:8]:
        if isinstance(gap, dict):
            graph_lines.append(clip("GAP · " + clip(gap.get("label"), 280) + " · " + clip(gap.get("reason"), 500)))

    relation_lines = []
    for row in (rel.get("dexNativeLinks") or [])[:8]:
        if isinstance(row, dict):
            relation_lines.append(clip(f"DEX→SO · {row.get('from','')} → {row.get('to','')} · {row.get('library','')} · confidence {float(row.get('confidence') or 0):.2f}"))
    for row in (rel.get("embeddedLibraryStringEdges") or [])[:6]:
        if isinstance(row, dict):
            relation_lines.append(clip(f"SO→SO · {row.get('from','')} → {row.get('to','')} · {row.get('value','')}"))
    for row in (rel.get("symbolEdges") or [])[:6]:
        if isinstance(row, dict):
            relation_lines.append(clip(f"IMPORT→EXPORT · {row.get('from','')} → {row.get('to','')} · {row.get('symbol','')}"))
    for row in (rel.get("dynamicSymbolEdges") or [])[:6]:
        if not isinstance(row, dict):
            continue
        line = f"DLSYM · {row.get('from','')} → {row.get('to','')} · {row.get('symbol','')}"
        xrefs = row.get("staticStringXrefs") or []
        if xrefs and isinstance(xrefs[0], dict):
            x = xrefs[0]
            line += " · " + str(x.get("sourceFunction") or f"sub_{as_int(x.get('xrefRva')):x}")
        relation_lines.append(clip(line))
    for row in (rel.get("jniDirectCallRefs") or [])[:6]:
        if isinstance(row, dict):
            relation_lines.append(clip(f"JNI BL · {row.get('sourceFunction','')} → {row.get('targetFunction','')} @ 0x{as_int(row.get('callRva')):x}"))
    for row in (rel.get("il2cppDirectCallRefs") or [])[:8]:
        if not isinstance(row, dict):
            continue
        src = str(row.get("sourceFunction") or "")
        source_methods = row.get("sourceMethodCandidates") or []
        if source_methods and isinstance(source_methods[0], dict):
            src = str(source_methods[0].get("label") or src)
        if not src:
            src = f"sub_{as_int(row.get('callRva')):x}"
        target = f"IL2CPP RVA 0x{as_int(row.get('targetRva')):x}"
        target_methods = row.get("targetMethods") or []
        if target_methods and isinstance(target_methods[0], dict):
            target = str(target_methods[0].get("label") or target)
        relation_lines.append(clip(f"IL2CPP BL · {src} → {target}"))
    for row in (rel.get("il2cppMethodContext") or [])[:8]:
        if not isinstance(row, dict):
            continue
        method = row.get("method") or {}
        label = str(method.get("label") or "IL2CPP method") if isinstance(method, dict) else "IL2CPP method"
        calls = row.get("outgoingManagedCalls") or []
        strings = row.get("stringRefs") or []
        offsets = row.get("thisOffsetCandidates") or []
        line = f"METHOD CTX · {label} · calls {len(calls)} · strings {len(strings)} · offsets {len(offsets)}"
        if calls and isinstance(calls[0], dict):
            target_method = calls[0].get("targetMethod") or {}
            if isinstance(target_method, dict) and target_method.get("label"):
                line += " · → " + str(target_method.get("label"))
        relation_lines.append(clip(line))

    cards = []
    for finding in findings[:48]:
        if not isinstance(finding, dict):
            continue
        evidence_lines = []
        for evidence in (finding.get("evidence") or [])[:12]:
            if isinstance(evidence, dict):
                evidence_lines.append(clip(
                    f"• {evidence.get('artifact','')} · {evidence.get('kind','')} · {evidence.get('value','')} {evidence.get('location','')}",
                    1000,
                ))
        cards.append({
            "title": clip(finding.get("title"), 500),
            "status": clip(finding.get("status"), 80),
            "confidence": float(finding.get("confidence") or 0),
            "rationale": clip(finding.get("rationale"), 2400),
            "evidenceLines": evidence_lines,
        })

    return {
        "schema": "modkit-re-ui-1.0",
        "reportState": report_state,
        "reportSizeBytes": report_size_bytes,
        "summaryText": summary_text,
        "findingCount": len(findings),
        "visibleFindingCount": len(cards),
        "controlCandidateCount": len(candidates),
        "controlCandidateLines": control_lines,
        "graphLines": graph_lines,
        "relationshipLines": relation_lines,
        "findings": cards,
        "targetProfile": copy.deepcopy(result.get("targetProfile") or {}),
        "applicationDiscovery": copy.deepcopy(result.get("applicationDiscovery") or {}),
        "inputSources": copy.deepcopy(inputs),
        "pipelineDiagnostics": copy.deepcopy(diag),
    }

def _dedupe_re_evidence(result):
    """Remove exact duplicate evidence rows without dropping unique facts."""
    def dedupe(rows):
        out, seen = [], set()
        for row in rows or []:
            if not isinstance(row, dict):
                out.append(row)
                continue
            key = json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out
    for finding in result.get("findings") or []:
        if isinstance(finding, dict) and isinstance(finding.get("evidence"), list):
            finding["evidence"] = dedupe(finding.get("evidence"))
    for candidate in result.get("controlCandidates") or []:
        if isinstance(candidate, dict) and isinstance(candidate.get("corroboratingEvidence"), list):
            candidate["corroboratingEvidence"] = dedupe(candidate.get("corroboratingEvidence"))
            candidate["evidenceCount"] = 1 + len(candidate["corroboratingEvidence"])
    return result


def _re_menu_snapshot(result):
    """Small fail-closed seed for Menu Builder; avoids parsing the full RE report."""
    natives = []
    for row in ((result.get("inventory") or {}).get("native") or []):
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("artifact") or row.get("path") or "")
        if Path(name).name == "libil2cpp.so":
            natives.append({k: row.get(k) for k in ("name", "artifact", "path", "sha256") if row.get(k) is not None})
    findings = []
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("status") not in {"confirmed", "correlated"}:
            continue
        row = {k: copy.deepcopy(finding.get(k)) for k in ("id", "title", "category", "status", "confidence", "rationale") if k in finding}
        row["evidence"] = copy.deepcopy((finding.get("evidence") or [])[:16])
        findings.append(row)
        if len(findings) >= 80:
            break
    return {
        "schema": "modkit-re-menu-seed-1.0",
        "apk": copy.deepcopy(result.get("apk") or {}),
        "inventory": {"native": natives},
        "controlCandidates": copy.deepcopy((result.get("controlCandidates") or [])[:200]),
        "findings": findings,
        "semanticVerification": copy.deepcopy(result.get("semanticVerification") or {}),
        "methodContextVerification": copy.deepcopy(result.get("methodContextVerification") or {}),
        "methodVerification": copy.deepcopy(result.get("methodVerification") or {}),
        "targetProfile": copy.deepcopy(result.get("targetProfile") or {}),
        "inputSources": copy.deepcopy(result.get("inputSources") or {}),
        "pipelineDiagnostics": copy.deepcopy(result.get("pipelineDiagnostics") or {}),
    }


def _load_menu_analysis(re_report_path):
    p = Path(re_report_path)
    sidecar = p.with_name(p.stem + ".menu.json")
    if sidecar.is_file():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return json.loads(p.read_text(encoding="utf-8"))


def re_analyze_apk(apk_path, output_path, metadata_path=None, library_path=None,
                   rodroid_dir=None, unity_report_path=None, il2cpp_report_path=None, cb=None,
                   input_mode=None, compact_return=False):
    """Cross-correlate DEX, native libraries and IL2CPP/Unity evidence.

    Dev22 uses sequential bounded stages for large IL2CPP applications:

    1. generic scan of an external ``libil2cpp.so`` (when supplied), persisted as
       compact JSON and released;
    2. specialized metadata/CodeRegistration + direct-call/method-context pass,
       likewise persisted and released;
    3. generic APK/DEX/metadata/Rodroid scan, followed by deterministic merging.

    This preserves the old evidence coverage while preventing the 100+ MiB ELF,
    full metadata attribution structures and the generic report from living in
    Python memory at the same time.
    """
    import gc
    import tempfile

    from modkit.reworkspace import correlate_apk
    from modkit.reworkspace.correlate import analyze_artifacts
    from modkit.mobile.app_discovery import build_application_discovery
    from modkit.mobile.target_profile import classify_report
    from modkit.reworkspace import (
        augment_structured_findings, augment_function_correlations,
        augment_method_verification, derive_control_candidates, augment_control_semantics,
        build_static_relationship_graph,
    )

    from modkit.reworkspace.pipeline import (
        write_json_stage as _write_stage_impl,
        merge_findings as _merge_findings,
        merge_generic_stage as _merge_generic_stage,
    )
    from modkit.reworkspace.cache import CorrelationCache
    from modkit.reworkspace.schema import ensure_report_contract

    def _write_stage(payload, prefix):
        return _write_stage_impl(payload, output_path, prefix)

    # Main generic scan deliberately excludes the external library when it has
    # already been analyzed in its own stage. Metadata/Rodroid files remain in
    # the main scan exactly as before.
    main_extras = []
    if metadata_path and os.path.isfile(metadata_path):
        main_extras.append(metadata_path)
    if rodroid_dir and os.path.isdir(rodroid_dir):
        for name in ("dump.cs", "script.json", "stringliteral.json"):
            p = os.path.join(rodroid_dir, name)
            if os.path.isfile(p):
                main_extras.append(p)

    generic_library_stage_path = None
    xref_stage_path = None
    staged_function_correlations = False
    try:
        # Stage 1: retain the generic native/string/JNI coverage of an externally
        # supplied libil2cpp.so, but do not retain its 100+ MiB bytes afterwards.
        if library_path and os.path.isfile(library_path):
            check(cb, "RE: общий native/string scan внешнего libil2cpp.so…")
            lib_path = Path(library_path)
            generic_library = analyze_artifacts([
                (f"extra/{lib_path.name}", lib_path.read_bytes())
            ])
            generic_library_stage_path = _write_stage(
                generic_library, "modkit-dev16-native-"
            )
            del generic_library
            gc.collect()

        # Stage 2: exact managed xref/method-context evidence.  Only the compact
        # relations/findings are retained between stages.
        if (il2cpp_report_path and os.path.isfile(il2cpp_report_path)
                and metadata_path and os.path.isfile(metadata_path)
                and library_path and os.path.isfile(library_path)):
            check(cb, "RE: IL2CPP xref/context prepass…")
            il2cpp_stage = None
            stage_report = None
            compact_stage = None
            try:
                il2cpp_stage = json.loads(Path(il2cpp_report_path).read_text(encoding="utf-8"))
                stage_report = {"il2cpp": il2cpp_stage, "findings": []}
                augment_function_correlations(
                    stage_report, apk_path=apk_path, library_path=library_path,
                    metadata_path=metadata_path,
                )
                compact_stage = {
                    "nativeRelations": stage_report.get("nativeRelations") or {},
                    "findings": [
                        x for x in (stage_report.get("findings") or [])
                        if x.get("id") == "re.il2cpp_static_call_references"
                    ],
                }
                xref_stage_path = _write_stage(
                    compact_stage, "modkit-dev16-xref-"
                )
                staged_function_correlations = True
            finally:
                del compact_stage, stage_report, il2cpp_stage
                gc.collect()

        # Stage 3: APK, DEX, metadata and Rodroid generic evidence.  The external
        # library has already been covered in stage 1 and is merged below.
        check(cb, "RE: инвентаризация APK, DEX и native…")
        cache = CorrelationCache(Path(output_path).resolve().parent / ".re-cache")
        cache_key = None
        cache_fps = []
        cache_hit = False
        try:
            cache_key, cache_fps = cache.identity([apk_path, *main_extras])
            result = cache.load(cache_key)
            cache_hit = isinstance(result, dict)
        except (OSError, ValueError, TypeError):
            result = None
        if result is None:
            apk_sha = cache_fps[0].sha256 if cache_fps else None
            result = correlate_apk(apk_path, main_extras, apk_sha256=apk_sha)
            if cache_key:
                try:
                    cache.store(cache_key, result)
                except (OSError, TypeError, ValueError):
                    pass
        else:
            check(cb, "RE: cache hit — generic APK correlation уже рассчитан")
            result = ensure_report_contract(result)
            if isinstance(result.get("apk"), dict):
                result["apk"]["path"] = str(apk_path)
        result["correlationCache"] = {
            "schema": "modkit-re-cache-status-1",
            "hit": bool(cache_hit),
            "key": cache_key,
            "namespace": cache.namespace,
            "inputs": [{"name": x.name, "size": x.size, "sha256": x.sha256} for x in cache_fps],
            "semantics": "Static generic evidence only; runtime/probe truth is never restored from this cache.",
        }

        if generic_library_stage_path and os.path.isfile(generic_library_stage_path):
            staged_generic = json.loads(Path(generic_library_stage_path).read_text(encoding="utf-8"))
            _merge_generic_stage(result, staged_generic)
            del staged_generic

        # Load structured engine reports only after generic scanning, so they do
        # not contribute to the scanner's peak RSS.
        for key, path in (("unity", unity_report_path), ("il2cpp", il2cpp_report_path)):
            if path and os.path.isfile(path):
                try:
                    result[key] = json.loads(Path(path).read_text(encoding="utf-8"))
                except Exception as exc:
                    result[key] = {"parseError": str(exc), "path": path}

        if staged_function_correlations and xref_stage_path and os.path.isfile(xref_stage_path):
            staged = json.loads(Path(xref_stage_path).read_text(encoding="utf-8"))
            relations = result.setdefault("nativeRelations", {})
            # These keys are specialized IL2CPP outputs.  They are authoritative
            # for this pass and do not replace unrelated JNI/native relations.
            relations.update(staged.get("nativeRelations") or {})
            _merge_findings(result, staged.get("findings") or [])
            del staged
        else:
            check(cb, "RE: статические function/xref связи…")
            augment_function_correlations(
                result, apk_path=apk_path, library_path=library_path,
                metadata_path=metadata_path,
            )

        augment_structured_findings(result)
        check(cb, "RE: universal method evidence…")
        augment_method_verification(result)
        result["controlCandidates"] = derive_control_candidates(result)
        check(cb, "RE: semantic/xref верификация методов…")
        augment_control_semantics(result)
        check(cb, "RE: построение статического relationship graph…")
        build_static_relationship_graph(result)
        check(cb, "RE: профиль target и Application Discovery…")
        result["applicationDiscovery"] = build_application_discovery(result)
        result["targetProfile"] = classify_report(result)

        # Keep the exact input provenance visible.  In split-APK workflows the
        # selected external pair is intentionally different from "inside base.apk";
        # hiding that fact made dev17's missing-xref bug very hard to diagnose.
        il2cpp_loaded = isinstance(result.get("il2cpp"), dict) and not (result.get("il2cpp") or {}).get("parseError")
        relations = result.get("nativeRelations") or {}
        xrefs = relations.get("il2cppDirectCallRefs") or []
        ctx_summary = relations.get("il2cppMethodContextSummary") or {}
        result["inputSources"] = {
            "mode": str(input_mode or "unspecified"),
            "apk": Path(apk_path).name if apk_path else None,
            "metadata": Path(metadata_path).name if metadata_path else None,
            "library": Path(library_path).name if library_path else None,
            "rodroid": Path(rodroid_dir).name if rodroid_dir else None,
            "il2cppReport": Path(il2cpp_report_path).name if il2cpp_report_path else None,
            "externalSelectedPair": str(input_mode or "").startswith("selected-external-pair"),
            "il2cppReportLoaded": bool(il2cpp_loaded),
        }
        result["pipelineDiagnostics"] = {
            "il2cppRows": sum(len((result.get("il2cpp") or {}).get(k, []) or [])
                              for k in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates")),
            "il2cppDirectCallRefs": len(xrefs),
            "contextMethods": int(ctx_summary.get("methods") or 0),
            "externalLibraryUsed": bool(library_path and os.path.isfile(library_path)),
            "managedXrefStatus": ("xref-evidence-present" if xrefs else
                                  "no-direct-bl-evidence" if il2cpp_loaded and library_path else
                                  "il2cpp-input-incomplete"),
            "methodVerification": result.get("methodVerification") or {},
            "typedContract": result.get("typedContract"),
            "genericCorrelationCacheHit": bool((result.get("correlationCache") or {}).get("hit")),
            "memoryModel": result.get("memoryModel"),
            "streamingDiagnostics": result.get("streamingDiagnostics") or {},
        }

        _dedupe_re_evidence(result)
        menu_output_path = str(Path(output_path).with_name(Path(output_path).stem + ".menu.json"))
        check(cb, "RE: сохранение компактного Menu Builder seed…")
        _atomic_stream_json(menu_output_path, _re_menu_snapshot(result), cb)

        ui_output_path = str(Path(output_path).with_name(Path(output_path).stem + ".ui.json"))
        check(cb, "RE: сохранение компактного UI-индекса…")
        ui_snapshot = _re_ui_snapshot(result, report_state="saving")
        _atomic_stream_json(ui_output_path, ui_snapshot, cb)

        check(cb, "RE: потоковое сохранение полного корреляционного отчёта…")
        _atomic_stream_json(output_path, result, cb, "RE: полный отчёт сохранён")

        ui_snapshot["reportState"] = "complete"
        ui_snapshot["reportSizeBytes"] = os.path.getsize(output_path)
        _atomic_stream_json(ui_output_path, ui_snapshot, cb)
        if compact_return:
            return json.dumps({
                "schema": result.get("schema", "modkit-re-1.2"),
                "findingCount": len(result.get("findings") or []),
                "controlCandidateCount": len(result.get("controlCandidates") or []),
                "il2cppXrefs": len(xrefs),
                "contextMethods": int(ctx_summary.get("methods") or 0),
                "targetProfile": result.get("targetProfile"),
                "applicationDiscovery": result.get("applicationDiscovery"),
                "inputSources": result.get("inputSources"),
                "pipelineDiagnostics": result.get("pipelineDiagnostics"),
                "menuSeedPath": menu_output_path,
            }, ensure_ascii=False, separators=(",", ":"))
        return json.dumps(result, ensure_ascii=False)
    finally:
        for stage_path in (generic_library_stage_path, xref_stage_path):
            if stage_path:
                try:
                    os.unlink(stage_path)
                except FileNotFoundError:
                    pass


def native_workspace_create(source_path, working_path, state_path, cb=None):
    from shutil import copyfile
    from modkit.reworkspace import NativeWorkspace
    check(cb, "Native Workspace: подготовка рабочей копии…")
    copyfile(source_path, working_path)
    ws = NativeWorkspace(working_path)
    state = {"schema": "modkit-native-state-1.0", "source": source_path,
             "sourceSha256": digest(source_path), "changes": []}
    Path(state_path).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps({"summary": ws.summary(), "sections": ws.sections()[:256]}, ensure_ascii=False)


def _native_state(state_path):
    p = Path(state_path)
    if not p.is_file():
        return {"schema": "modkit-native-state-1.0", "changes": []}
    return json.loads(p.read_text(encoding="utf-8"))


def native_workspace_info(working_path, state_path):
    from modkit.reworkspace import NativeWorkspace
    ws = NativeWorkspace(working_path)
    state = _native_state(state_path)
    return json.dumps({"summary": ws.summary(), "sections": ws.sections(),
                       "changes": state.get("changes", [])}, ensure_ascii=False)


def native_workspace_search(working_path, query, limit=200):
    from modkit.reworkspace import NativeWorkspace
    ws = NativeWorkspace(working_path)
    result = {"symbols": ws.symbols(query, int(limit)), "strings": ws.strings(query, limit=int(limit))}
    return json.dumps(result, ensure_ascii=False)


def native_workspace_xrefs(working_path, rva, limit=200):
    from modkit.reworkspace import NativeWorkspace
    ws = NativeWorkspace(working_path)
    value = int(str(rva), 0)
    return json.dumps(ws.direct_calls({value}, limit=int(limit)), ensure_ascii=False)


def native_workspace_disasm(working_path, rva, size=128):
    from modkit.reworkspace import NativeWorkspace
    ws = NativeWorkspace(working_path)
    value = int(str(rva), 0)
    return json.dumps(ws.disassemble(value, int(size)), ensure_ascii=False)


def native_workspace_patch(working_path, state_path, rva, mode, payload, note="", cb=None):
    from modkit.reworkspace import NativeWorkspace
    value = int(str(rva), 0)
    ws = NativeWorkspace(working_path)
    check(cb, f"Native Workspace: изменение RVA 0x{value:x}…")
    if str(mode).lower() == "asm":
        change = ws.patch_asm(value, str(payload), str(note))
    elif str(mode).lower() == "hex":
        change = ws.patch_hex(value, str(payload), str(note))
    else:
        raise ValueError("mode must be asm or hex")
    Path(working_path).write_bytes(ws.elf.blob)
    state = _native_state(state_path)
    state.setdefault("changes", []).append(change)
    Path(state_path).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(change, ensure_ascii=False)


def native_workspace_undo(working_path, state_path):
    from modkit.elf.reader import ElfFile
    state = _native_state(state_path)
    changes = state.setdefault("changes", [])
    if not changes:
        return json.dumps({"undone": False}, ensure_ascii=False)
    change = changes.pop()
    elf = ElfFile.open(working_path)
    elf.write_at_rva(int(change["rva"]), bytes.fromhex(change["old_hex"]))
    Path(working_path).write_bytes(elf.blob)
    Path(state_path).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps({"undone": True, "change": change}, ensure_ascii=False)


def native_workspace_save(working_path, output_path):
    from shutil import copyfile
    copyfile(working_path, output_path)
    return json.dumps({"path": output_path, "sha256": digest(output_path)}, ensure_ascii=False)


def patchpack_inspect(source_apk, patch_zip, output_report=None, cb=None):
    from modkit.patchpack import inspect_pack
    check(cb, "Patch Pack: проверка DEX, ABI и native-зависимостей…")
    result = inspect_pack(source_apk, patch_zip)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)


def patchpack_apply_unsigned(source_apk, patch_zip, output_apk, output_report=None, cb=None):
    from modkit.patchpack import apply_pack
    check(cb, "Patch Pack: применение к копии APK…")
    result = apply_pack(source_apk, patch_zip, output_apk)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)


def _deep_menu_analysis(deep_dir, source_apk=None, cb=None):
    """Collect only fail-closed Deep Resolver menu candidates from one input pair."""
    root = Path(deep_dir)
    if not root.is_dir():
        raise ValueError('Deep Resolver ещё не запускался')
    controls = []
    reviewed = 0
    rejected = []
    meta_hashes = set()
    lib_hashes = set()
    for path in sorted(root.glob('method-*.json')):
        check(cb)
        try:
            row = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            rejected.append({'file': path.name, 'reason': 'invalid-json'})
            continue
        reviewed += 1
        identity = row.get('inputIdentity') or {}
        if len(str(identity.get('metadataSha256') or '')) == 64:
            meta_hashes.add(str(identity['metadataSha256']).lower())
        if len(str(identity.get('librarySha256') or '')) == 64:
            lib_hashes.add(str(identity['librarySha256']).lower())
        candidate = row.get('menuCandidate')
        eligibility = row.get('menuEligibility') or {}
        runtime = row.get('runtimeTruth') or {}
        if not eligibility.get('eligible') or not isinstance(candidate, dict):
            rejected.append({'file': path.name, 'methodId': row.get('metadataMethodId'),
                             'reason': eligibility.get('blocker') or 'not-menu-eligible'})
            continue
        if runtime.get('confirmed') is True:
            rejected.append({'file': path.name, 'methodId': row.get('metadataMethodId'),
                             'reason': 'static-deep-result-must-not-claim-runtime-confirmed'})
            continue
        controls.append(dict(candidate))
    # Dev26: collapse metadata aliases/thunks which resolve to the same canonical implementation.
    # The strongest candidate wins; this prevents duplicate buttons for one native body.
    dedup = {}
    for candidate in controls:
        canonical = candidate.get('canonicalImplementationRva') or candidate.get('evidenceRva')
        key = (int(canonical) if isinstance(canonical, int) else str(candidate.get('id')),
               str(candidate.get('bindingSuggestion') or ''))
        score = (float(candidate.get('semanticConfidence') or 0.0),
                 float(candidate.get('confidence') or 0.0), int(candidate.get('evidenceCount') or 0))
        prev = dedup.get(key)
        if prev is None or score > prev[0]:
            dedup[key] = (score, candidate)
    controls = [x[1] for x in dedup.values()]
    controls.sort(key=lambda c: (-float(c.get('semanticConfidence') or 0.0),
                                 -float(c.get('confidence') or 0.0), str(c.get('title') or '').casefold()))
    if len(meta_hashes) > 1 or len(lib_hashes) > 1:
        raise ValueError('Deep Resolver каталог содержит результаты от разных metadata/libil2cpp пар; выполните анализ заново')
    analysis = {'controlCandidates': controls, 'findings': [], 'inventory': {'native': []}, 'apk': {}}
    if lib_hashes:
        analysis['inventory']['native'].append({'name': 'libil2cpp.so', 'soname': 'libil2cpp.so',
                                                'sha256': next(iter(lib_hashes))})
    if source_apk:
        analysis['apk']['sha256'] = digest(source_apk, cb)
    return analysis, {'deepResults': reviewed, 'eligibleControls': len(controls), 'deduplicatedControls': len(controls),
                      'rejected': rejected, 'metadataSha256': next(iter(meta_hashes), None),
                      'librarySha256': next(iter(lib_hashes), None)}



def _autopilot_category(tags, label=''):
    tags = {str(x).casefold() for x in (tags or ())}
    low = str(label or '').casefold()
    if tags & {'health', 'damage', 'combat'} or any(x in low for x in ('damage', 'health', 'attack', 'combat')):
        return 'Combat'
    if tags & {'movement'} or any(x in low for x in ('speed', 'move', 'jump', 'motion')):
        return 'Movement'
    if tags & {'economy', 'resource', 'progression', 'currency', 'inventory', 'cooldown'} or any(x in low for x in ('money', 'coin', 'currency', 'level', 'exp', 'resource', 'inventory', 'cooldown')):
        return 'Progression / Economy'
    if tags & {'world', 'state', 'camera'} or any(x in low for x in ('weather', 'world', 'time', 'camera', 'fov')):
        return 'World / State'
    if tags & {'debug', 'cheat'} or any(x in low for x in ('debug', 'console', 'cheat')):
        return 'Developer / Debug'
    return 'General'


def _autopilot_catalog_candidates(catalog_path, *, max_candidates=48, per_class=4, cb=None):
    """Rank a bounded Deep queue; dev27 prefers the shared Evidence Graph.

    Graph evidence is discovery/ranking only. ABI, resolver safety and menu
    eligibility are still re-proved fail-closed by ``deep_resolve_method``.
    """
    ranked = []
    path = Path(catalog_path)
    if not path.is_file():
        raise ValueError('Полный metadata-каталог отсутствует')

    graph = path.with_name('analysis.evidence-graph.jsonl')
    graph_meta = path.with_name('analysis.evidence-graph.meta.json')
    graph_usable = graph.is_file()
    graph_source = graph
    if graph_usable and graph_meta.is_file():
        try:
            gm=json.loads(graph_meta.read_text(encoding='utf-8'))
            expected=int(((gm.get('sourceIdentity') or {}).get('catalogBytes')) or -1)
            if expected >= 0 and expected != path.stat().st_size:
                graph_usable=False
            else:
                ap = path.with_name(str(gm.get('autopilotIndexFile') or ''))
                if ap.is_file():
                    graph_source = ap
        except (OSError, ValueError, TypeError):
            graph_usable=False

    if graph_usable:
        from modkit.mobile.gameplay import _noise, domains_for
        with graph_source.open('r', encoding='utf-8') as fh:
            for n,line in enumerate(fh):
                if n % 4096 == 0: check(cb)
                if not line.strip(): continue
                try: row=json.loads(line)
                except ValueError: continue
                rva=row.get('rva'); mid=row.get('metadataMethodId')
                if not isinstance(rva,int) or rva<=0 or not isinstance(mid,int): continue
                if not row.get('applicationOwned'): continue
                # Autopilot is an executable-binding queue, not the discovery
                # graph itself. Virtual/interface slots remain review until the
                # full receiver/vtable resolver proves a concrete target.
                slot = row.get('metadataSlot')
                if slot is not None and int(slot) != 0xFFFF: continue
                if row.get('generic') or row.get('abstract'): continue
                role = str(row.get('methodRole') or '')
                if role in {'lifecycle','generated','query'}: continue
                label=str(row.get('label') or ''); cls=str(row.get('class') or '')
                if _noise(cls+' '+label): continue
                named_domains=domains_for(label, owner=cls) or []
                domains=list(dict.fromkeys(row.get('semanticDomains') or row.get('domains') or named_domains or []))
                typed=[a for a in (row.get('typedFieldAccesses') or []) if a.get('domains')]
                # Pure bridge/conduit adjacency is not enough for an Autopilot slot.
                direct_domains=set(row.get('domains') or [])
                field_domains={d for a in typed for d in (a.get('domains') or [])}
                if not domains and not typed: continue
                low=label.casefold(); name=str(row.get('name') or '')
                score=52.0
                stores=sum(1 for a in typed if a.get('access')=='store')
                loads=sum(1 for a in typed if a.get('access')=='load')
                score += min(36.0, stores*18.0 + loads*5.0)
                score += min(16.0, 4.0*len(field_domains))
                score += min(12.0, 3.0*len(direct_domains))
                score += min(10.0, 2.0*len(domains))
                if named_domains: score += min(14.0, 7.0*len(named_domains))
                if row.get('isStatic'): score += 5.0
                if any(x in low for x in ('set','apply','add','remove','enable','disable','change','refresh','update')): score+=6.0
                if any(x in low for x in ('get_','get','is','has')) and not stores: score-=2.0
                if '::.ctor' in label or '::.cctor' in label: score-=18.0
                if cls.endswith('Wrap') or cls.endswith('Wrapper'): score-=10.0
                callers=int(row.get('callerCount') if row.get('callerCount') is not None else len(row.get('callers') or []))
                callees=int(row.get('calleeCount') if row.get('calleeCount') is not None else len(row.get('callees') or []))
                score += min(8.0, float(callers+callees)*0.5)
                binding='review'
                if name.startswith(('Set','set_')) and stores:
                    binding='number_setter'
                elif name.startswith(('Enable','Disable','Toggle')):
                    binding='bool_setter'
                elif not name.startswith(('get_','Get','Is','Has')):
                    binding='action'
                ranked.append({
                    'metadataMethodId':int(mid),'label':label,'class':cls,
                    'bindingSuggestion':binding,'isStatic':bool(row.get('isStatic')),
                    'relationStatus':'evidence-graph','semanticTags':domains,
                    'category':_autopilot_category(domains,label),'score':round(score,2),'rva':int(rva),
                    'typedFieldCount':len(typed),'typedFieldStoreCount':stores,
                    'selectionPolicy':'confirmed-address+evidence-graph+application-owned; Deep Resolver re-proves ABI/binding',
                })
    else:
        # Legacy/small-fixture path keeps dev26 structural semantics.
        with path.open('r', encoding='utf-8') as fh:
            for n, line in enumerate(fh):
                if n % 4096 == 0: check(cb)
                if not line.strip(): continue
                try: row=json.loads(line)
                except ValueError: continue
                binding=str(row.get('binding_suggestion') or '')
                if binding not in {'action','bool_setter','number_setter'}: continue
                if row.get('generic') or row.get('abstract'): continue
                if not row.get('address_confirmed') or not row.get('abi_shape_supported'): continue
                if not row.get('application_owned'): continue
                if not isinstance(row.get('rva'),int) or int(row.get('rva') or 0)<=0: continue
                tags=list(row.get('semantic') or ()); role=str(row.get('method_role') or '')
                score=55.0
                if row.get('relation_status')=='observed-static-xref': score+=16.0
                if row.get('auto_binding_safe'): score+=10.0
                if row.get('is_static'): score+=4.0
                score += {'bool_setter':5.0,'action':4.0,'number_setter':2.0}.get(binding,0.0)
                score += min(12.0,3.0*len(set(tags)))
                if role in {'setter','action','command'}: score+=4.0
                if str(row.get('provenance') or '')=='game-primary': score+=6.0
                incoming=int(row.get('static_incoming_direct_bl_count') or 0); score+=min(6.0,float(incoming))
                ranked.append({'metadataMethodId':int(row.get('metadata_method_id')),'label':str(row.get('label') or ''),
                    'class':str(row.get('class') or ''),'bindingSuggestion':binding,'isStatic':bool(row.get('is_static')),
                    'relationStatus':str(row.get('relation_status') or 'not-observed'),'semanticTags':tags,
                    'category':_autopilot_category(tags,row.get('label')),'score':round(score,2),'rva':int(row.get('rva')),
                    'selectionPolicy':'confirmed-address+supported-ABI+application-owned+call-shape; names only rank'})

    ranked.sort(key=lambda x:(-float(x['score']),0 if x['relationStatus'] in {'observed-static-xref','evidence-graph'} else 1,
                               str(x['class']).casefold(),str(x['label']).casefold()))
    chosen=[]; per=collections.Counter(); binding_counts=collections.Counter(); category_counts=collections.Counter()
    for item in ranked:
        cls=item['class'] or '<global>'; cat=item['category']
        if per[cls] >= int(per_class): continue
        # Keep useful category diversity without hard-coded games/classes.
        if category_counts[cat] >= max(4,int(max_candidates)//3): continue
        chosen.append(item); per[cls]+=1; binding_counts[item['bindingSuggestion']]+=1; category_counts[cat]+=1
        if len(chosen)>=int(max_candidates): break
    return {'schema':'modkit-menu-autopilot-queue-1.1','source':'evidence-graph' if graph_usable else 'catalog-legacy',
            'totalRanked':len(ranked),'selected':chosen,'bindingCounts':dict(binding_counts),
            'categoryCounts':dict(category_counts),
            'policy':'discovery ranking only; every selected method must independently pass Deep Resolver'}


def deep_resolve_autopilot(metadata_path, library_path, catalog_path, deep_dir, dump_dir=None,
                           max_deep=24, target_controls=12, cb=None):
    """Resolve a diverse bounded queue until enough menu-eligible methods are proven."""
    deep = Path(deep_dir); deep.mkdir(parents=True, exist_ok=True)
    queue = _autopilot_catalog_candidates(catalog_path, max_candidates=max(8, int(max_deep)*2), cb=cb)
    processed=[]; eligible=[]; blocked=[]
    category_hits=collections.Counter()
    import inspect
    supports_shared = '_shared_elf' in inspect.signature(deep_resolve_method).parameters
    shared_elf = Elf(library_path, cb) if supports_shared and Path(library_path).is_file() else None
    try:
        for item in queue['selected']:
            check(cb, f"Menu Autopilot: Deep Resolver {len(processed)+1}/{min(len(queue['selected']), int(max_deep))} · {item['label'][:80]}")
            mid=int(item['metadataMethodId'])
            out=deep / f'method-{mid}.json'
            try:
                if shared_elf is not None:
                    resolved = deep_resolve_method(metadata_path, library_path, catalog_path, mid,
                                                   str(out), cb, dump_dir, _shared_elf=shared_elf)
                else:
                    resolved = deep_resolve_method(metadata_path, library_path, catalog_path, mid,
                                                   str(out), cb, dump_dir)
                row=json.loads(resolved)
            except Exception as exc:
                blocked.append({'metadataMethodId':mid,'label':item['label'],'reason':'deep-resolver-error','detail':str(exc)[:240]})
                processed.append(mid)
                if len(processed)>=int(max_deep): break
                continue
            processed.append(mid)
            cand=row.get('menuCandidate') if (row.get('menuEligibility') or {}).get('eligible') else None
            if isinstance(cand, dict):
                cand['category']=item['category']
                cand['autopilotScore']=item['score']
                # Persist enriched candidate so later manual Menu Builder entry uses the same category.
                row['menuCandidate']=cand
                out.write_text(json.dumps(row, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
                eligible.append({'metadataMethodId':mid,'label':item['label'],'category':item['category'],
                                 'bindingSuggestion':cand.get('bindingSuggestion'),'score':item['score']})
                category_hits[item['category']]+=1
            else:
                blocked.append({'metadataMethodId':mid,'label':item['label'],
                                'reason':(row.get('menuEligibility') or {}).get('blocker') or 'deep-not-eligible'})
            # Stop only after a useful diverse menu has emerged, not merely N hits from one class/category.
            if (len(eligible) >= int(target_controls) and len(category_hits) >= min(3, int(target_controls))):
                break
            if len(processed)>=int(max_deep):
                break
    finally:
        if shared_elf is not None:
            shared_elf.close()
    return {'schema':'modkit-menu-autopilot-deep-1.0','queue':queue,'processed':processed,
            'processedCount':len(processed),'eligible':eligible,'eligibleCount':len(eligible),
            'blocked':blocked[:128],'categories':dict(category_hits),
            'runtimeTruth':'not-observed-by-static-analysis'}


def menu_autopilot_prepare(metadata_path, library_path, catalog_path, deep_dir, source_apk,
                           menu_json_path, project_dir, output_report=None, output_preflight=None,
                           dump_dir=None, title='ModKit Autopilot Menu', max_deep=24,
                           target_controls=12, cb=None):
    """Dev26 full automatic static pipeline: catalogue -> Deep -> typed Menu -> ELF preflight."""
    check(cb, 'Menu Autopilot: универсальный отбор из полного metadata-каталога…')
    batch=deep_resolve_autopilot(metadata_path, library_path, catalog_path, deep_dir, dump_dir,
                                 int(max_deep), int(target_controls), cb)
    check(cb, 'Menu Autopilot: дедупликация и построение MenuSpec…')
    prepared=json.loads(menu_auto_prepare_from_deep(deep_dir, menu_json_path, source_apk, project_dir,
                                                    None, output_preflight, title, cb))
    result={'schema':'modkit-menu-autopilot-prepare-1.0','batch':batch,**prepared,
            'pipeline':['full-catalog-structural-prefilter','bounded-deep-resolver','deduplicated-typed-menu',
                        'apk-elf-auto-confirm','payload-preflight'],
            'policy':'fail-closed; numeric setters without independently reviewed ranges remain review'}
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return json.dumps(result, ensure_ascii=False)


def menu_seed_from_deep(deep_dir, menu_json_path, project_dir, title="ModKit Deep Menu", cb=None):
    """Seed Menu Builder only from Deep Resolver rows which passed every static gate."""
    from modkit.menu import spec_from_analysis, write_project
    analysis, stats = _deep_menu_analysis(deep_dir, cb=cb)
    spec = spec_from_analysis(analysis, title)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding='utf-8')
    project = write_project(spec, project_dir)
    return json.dumps({
        'schema': 'modkit-deep-menu-seed-1.1', **stats,
        'spec': spec.json(), 'project': project,
        'policy': 'Deep Resolver full static gates; executable binding remains unset until APK ELF preflight',
    }, ensure_ascii=False)


def menu_auto_prepare_from_deep(deep_dir, menu_json_path, source_apk, project_dir,
                                output_report=None, output_preflight=None,
                                title="ModKit Deep Menu", cb=None):
    """Dev24 one-pass Deep Resolver -> Menu -> ELF auto-confirm -> preflight."""
    from modkit.menu import spec_from_analysis, auto_confirm_bindings, review_preflight, write_project
    check(cb, 'Deep Resolver → Menu: сбор подтверждённых static candidates…')
    analysis, stats = _deep_menu_analysis(deep_dir, source_apk=source_apk, cb=cb)
    spec = spec_from_analysis(analysis, title)
    check(cb, 'Deep Resolver → Menu: signature/ABI/resolver + APK ELF auto-confirm…')
    confirm = auto_confirm_bindings(spec, source_apk)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding='utf-8')
    project = write_project(spec, project_dir)
    check(cb, 'Deep Resolver → Menu: payload preflight…')
    preflight = review_preflight(spec, source_apk)
    result = {
        'schema': 'modkit-deep-menu-auto-prepare-1.0', **stats,
        'confirm': confirm, 'preflight': preflight, 'project': project, 'spec': spec.json(),
        'pipeline': ['deep-static-gates', 'menu-spec', 'apk-elf-auto-confirm', 'project', 'payload-preflight'],
        'runtimeTruth': 'not-observed-by-static-analysis',
    }
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    if output_preflight:
        Path(output_preflight).write_text(json.dumps(preflight, ensure_ascii=False, indent=2), encoding='utf-8')
    return json.dumps(result, ensure_ascii=False)


def menu_seed_from_re(re_report_path, menu_json_path, project_dir, title="ModKit Menu", cb=None):
    from modkit.menu import spec_from_analysis, write_project
    check(cb, "Menu Builder: формирование элементов из подтверждённых находок…")
    analysis = _load_menu_analysis(re_report_path)
    spec = spec_from_analysis(analysis, title)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding="utf-8")
    result = write_project(spec, project_dir)
    return json.dumps({"spec": spec.json(), "project": result}, ensure_ascii=False)


def _menu_spec_from_json_path(menu_json_path):
    from modkit.menu import MenuControl, MenuSpec
    raw = json.loads(Path(menu_json_path).read_text(encoding="utf-8"))
    controls = []
    for item in raw.get("controls", []):
        controls.append(MenuControl(
            id=str(item.get("id", "")), title=str(item.get("title", "")),
            type=str(item.get("type", "label")), category=str(item.get("category", "General")),
            finding_id=item.get("finding_id"), rva=item.get("rva"),
            min_value=item.get("min_value"), max_value=item.get("max_value"),
            default=item.get("default"), note=str(item.get("note", "")),
            binding=item.get("binding"), target_so=str(item.get("target_so", "libil2cpp.so")),
            is_static=bool(item.get("is_static", True)), value_type=str(item.get("value_type") or "auto"),
            suggested_type=item.get("suggested_type"), evidence_rva=item.get("evidence_rva"),
            evidence_source=str(item.get("evidence_source", "")), evidence_kind=str(item.get("evidence_kind", "")),
            evidence_location=str(item.get("evidence_location", "")),
            evidence_confidence=item.get("evidence_confidence"), evidence_status=str(item.get("evidence_status", "")),
            evidence_count=int(item.get("evidence_count", 0) or 0), corroborating_evidence=list(item.get("corroborating_evidence") or [])[:24],
            suggested_target_so=item.get("suggested_target_so"),
            suggested_binding=item.get("suggested_binding"), evidence_is_static=item.get("evidence_is_static"),
            binding_blocker=item.get("binding_blocker"), evidence_signature=str(item.get("evidence_signature", "")),
            call_abi=str(item.get("call_abi", "native")), resolver_rva=item.get("resolver_rva"),
            resolver_kind=item.get("resolver_kind"), resolver_label=str(item.get("resolver_label", "")),
            resolver_source=str(item.get("resolver_source", "")),
            resolver_verified=bool(item.get("resolver_verified", False)),
            resolver_match=str(item.get("resolver_match", "")),
            resolver_target_class=str(item.get("resolver_target_class", "")),
            resolver_contract_source=str(item.get("resolver_contract_source", "")),
            resolver_signature=str(item.get("resolver_signature", "")),
            semantic_verified=(bool(item.get("semantic_verified")) if "semantic_verified" in item else None),
            semantic_status=str(item.get("semantic_status", "")),
            semantic_confidence=(float(item.get("semantic_confidence")) if item.get("semantic_confidence") is not None else None),
            semantic_tags=list(item.get("semantic_tags") or [])[:24],
            semantic_evidence=list(item.get("semantic_evidence") or [])[:24],
            semantic_blocker=item.get("semantic_blocker"),
            context_verified=(bool(item.get("context_verified")) if "context_verified" in item else None),
            context_status=str(item.get("context_status", "")),
            context_confidence=(float(item.get("context_confidence")) if item.get("context_confidence") is not None else None),
            context_evidence=list(item.get("context_evidence") or [])[:24],
            context_blocker=item.get("context_blocker"),
            gameplay_relevance=(int(item.get("gameplay_relevance")) if item.get("gameplay_relevance") is not None else None),
            gameplay_relevance_tier=str(item.get("gameplay_relevance_tier", "")),
            probe_kind=item.get("probe_kind"), probe_owner=str(item.get("probe_owner", "")),
            probe_field=str(item.get("probe_field", "")), probe_offset=item.get("probe_offset"),
            probe_primitive=str(item.get("probe_primitive", "")), probe_status=str(item.get("probe_status", "")),
            method_verification=dict(item.get("method_verification") or {}),
        ))
    return MenuSpec(title=str(raw.get("title", "ModKit Menu")), icon_text=str(raw.get("iconText", "MK")),
                    controls=controls, target_sha256=str(raw.get("targetSha256", "")),
                    source_apk_sha256=str(raw.get("sourceApkSha256", "")))



def menu_probe_prepare_from_gameplay(coverage_path, menu_json_path, source_apk, project_dir,
                                     graph_meta_path=None, output_report=None,
                                     title="ModKit Runtime Probe", max_probes=48, cb=None):
    """Build a read-only runtime WATCH/PROBE MenuSpec from exact gameplay fields."""
    from modkit.menu import probe_spec_from_gameplay, review_preflight, write_project
    check(cb, "Runtime Probe: exact gameplay fields → read-only WATCH controls…")
    coverage = json.loads(Path(coverage_path).read_text(encoding="utf-8"))
    spec = probe_spec_from_gameplay(coverage, title=title, max_probes=int(max_probes))
    if graph_meta_path and Path(graph_meta_path).is_file():
        meta = json.loads(Path(graph_meta_path).read_text(encoding="utf-8"))
        ident = meta.get("sourceIdentity") or {}
        spec.target_sha256 = str(ident.get("librarySha256") or "")
    if source_apk and Path(source_apk).is_file():
        import hashlib
        h = hashlib.sha256()
        with Path(source_apk).open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        spec.source_apk_sha256 = h.hexdigest()
    Path(menu_json_path).parent.mkdir(parents=True, exist_ok=True)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding="utf-8")
    project = write_project(spec, project_dir)
    preflight = review_preflight(spec, source_apk)
    result = {
        "schema": "modkit-runtime-probe-prepare-1.0",
        "controls": len(spec.controls),
        "readOnlyProbes": sum(1 for c in spec.controls if c.probe_kind is not None),
        "preflight": preflight,
        "project": project,
        "spec": spec.json(),
        "runtimeTruth": "not-observed-until-device-probe",
    }
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)

def menu_project_from_spec(menu_json_path, project_dir, cb=None):
    from modkit.menu import write_project
    check(cb, "Menu Builder: генерация проекта…")
    spec = _menu_spec_from_json_path(menu_json_path)
    return json.dumps(write_project(spec, project_dir), ensure_ascii=False)


def menu_auto_prepare_from_re(re_report_path, menu_json_path, source_apk, project_dir,
                              output_report=None, output_preflight=None, title="ModKit Menu", cb=None):
    from modkit.menu import spec_from_analysis, auto_confirm_bindings, review_preflight, write_project
    check(cb, "Menu Builder: RE → candidates → signature/ELF auto-confirm…")
    analysis = _load_menu_analysis(re_report_path)
    spec = spec_from_analysis(analysis, title)
    confirm = auto_confirm_bindings(spec, source_apk)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding="utf-8")
    project = write_project(spec, project_dir)
    preflight = review_preflight(spec, source_apk)
    result = {"schema": "modkit-menu-auto-prepare-1.0", "confirm": confirm,
              "preflight": preflight, "project": project, "spec": spec.json()}
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_preflight:
        Path(output_preflight).write_text(json.dumps(preflight, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)


def menu_auto_confirm(menu_json_path, source_apk, project_dir, output_report=None, cb=None):
    from modkit.menu import auto_confirm_bindings, write_project
    check(cb, "Menu Builder: автоподтверждение сигнатур/RVA по исходному APK…")
    spec = _menu_spec_from_json_path(menu_json_path)
    result = auto_confirm_bindings(spec, source_apk)
    Path(menu_json_path).write_text(json.dumps(spec.json(), ensure_ascii=False, indent=2), encoding="utf-8")
    result["project"] = write_project(spec, project_dir)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)


def menu_review_preflight(menu_json_path, source_apk, output_report=None, cb=None):
    from modkit.menu import review_preflight
    check(cb, "Menu Builder: сводная проверка готовности к payload…")
    spec = _menu_spec_from_json_path(menu_json_path)
    result = review_preflight(spec, source_apk)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)


def menu_validate_spec(menu_json_path, source_apk, output_report=None, cb=None):
    from modkit.menu import validate_bindings
    check(cb, "Menu Builder: проверка RVA по исходному APK…")
    spec = _menu_spec_from_json_path(menu_json_path)
    result = validate_bindings(spec, source_apk)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)



def menu_payload_from_runtime(menu_json_path, source_apk, runtime_so, output_zip, output_report=None, cb=None):
    from modkit.menu import write_patch_payload
    check(cb, "Menu Builder: упаковка native runtime в DEX-free Patch Pack…")
    spec = _menu_spec_from_json_path(menu_json_path)
    result = write_patch_payload(spec, source_apk, runtime_so, output_zip)
    if output_report:
        Path(output_report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(result, ensure_ascii=False)

def menu_export_project(project_dir, menu_json_path, output_zip, cb=None):
    check(cb, "Menu Builder: упаковка проекта…")
    root = Path(project_dir)
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as z:
        if Path(menu_json_path).is_file():
            z.write(menu_json_path, "modkit-menu.json")
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                check(cb)
                if p.is_file():
                    z.write(p, p.relative_to(root).as_posix())
    return output_zip
