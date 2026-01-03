//! \file       ArcXP3.cs
//! \date       Wed Jul 16 13:58:17 2014
//! \brief      KiriKiri engine archive implementation.
//
// Copyright (C) 2014-2017 by morkt
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media.Imaging;
using GameRes.Compression;
using GameRes.Formats.GUI;
using GameRes.Formats.Strings;
using GameRes.Utility;
using GARbro.GUI;

namespace GameRes.Formats.KiriKiri
{
    public struct Xp3Segment
    {
        public bool IsCompressed;
        public long Offset;
        public uint Size;
        public uint PackedSize;
    }

    public class Xp3Entry : PackedEntry
    {
        List<Xp3Segment> m_segments = new List<Xp3Segment>();

        public bool IsEncrypted { get; set; }
        public ICrypt Cipher { get; set; }
        public List<Xp3Segment> Segments { get { return m_segments; } }
        public uint Hash { get; set; }
        public object Extra { get; set; }

        public void SetOrder()
        {
            (Cipher as CxEncryption).PrologOrder = KeyAnalyze.PrologOrder;
            (Cipher as CxEncryption).OddBranchOrder = KeyAnalyze.OddBranchOrder;
            (Cipher as CxEncryption).EvenBranchOrder = KeyAnalyze.EvenBranchOrder;
        }

    }

    public class Xp3Options : ResourceOptions
    {
        public int Version { get; set; }
        public ICrypt Scheme { get; set; }
        public bool CompressIndex { get; set; }
        public bool CompressContents { get; set; }
        public bool RetainDirs { get; set; }
    }

    [Serializable]
    public class Xp3Scheme : ResourceScheme
    {
        public IDictionary<string, ICrypt> KnownSchemes;
        public ISet<string> NoCryptTitles;
    }

    // Archive version 1: encrypt file first, then calculate checksum
    //         version 2: calculate checksum, then encrypt

    [Export(typeof(ArchiveFormat))]
    public class Xp3Opener : ArchiveFormat
    {
        public override string Tag { get { return "XP3"; } }
        public override string Description { get { return arcStrings.XP3Description; } }
        public override uint Signature { get { return 0x0d335058; } }
        public override bool IsHierarchic { get { return true; } }
        public override bool CanWrite { get { return true; } }

        public Xp3Opener()
        {
            Signatures = new uint[] { 0x0d335058, 0x00905A4D, 0 };
            Extensions = new[] { "xp3", "exe" };
            ContainedFormats = new[] { "TLG", "BMP", "PNG", "JPEG", "OGG", "WAV", "TXT" };
        }

        static readonly byte[] s_xp3_header = {
            (byte)'X', (byte)'P', (byte)'3', 0x0d, 0x0a, 0x20, 0x0a, 0x1a, 0x8b, 0x67, 0x01
        };

        public bool ForceEncryptionQuery = true;

        internal static readonly ICrypt NoCryptAlgorithm = new NoCrypt();

        public override ArcFile TryOpen(ArcView file)
        {
            long base_offset = 0;
            if (0x5a4d == file.View.ReadUInt16(0)) // 'MZ'
                base_offset = SkipExeHeader(file, s_xp3_header);
            if (!file.View.BytesEqual(base_offset, s_xp3_header))
                return null;
            long dir_offset = base_offset + file.View.ReadInt64(base_offset + 0x0b);
            if (dir_offset < 0x13 || dir_offset >= file.MaxOffset)
                return null;
            if (0x80 == file.View.ReadUInt32(dir_offset))
            {
                dir_offset = base_offset + file.View.ReadInt64(dir_offset + 9);
                if (dir_offset < 0x13 || dir_offset >= file.MaxOffset)
                    return null;
            }
            int header_type = file.View.ReadByte(dir_offset);
            if (0 != header_type && 1 != header_type)
                return null;

            Stream header_stream;
            if (0 == header_type) // read unpacked header
            {
                long header_size = file.View.ReadInt64(dir_offset + 1);
                if (header_size > uint.MaxValue)
                    return null;
                header_stream = file.CreateStream(dir_offset + 9, (uint)header_size);
            }
            else // read packed header
            {
                long packed_size = file.View.ReadInt64(dir_offset + 1);
                if (packed_size > uint.MaxValue)
                    return null;
                long header_size = file.View.ReadInt64(dir_offset + 9);
                using (var input = file.CreateStream(dir_offset + 17, (uint)packed_size))
                    header_stream = ZLibCompressor.DeCompress(input);
            }

            var crypt_algorithm = new Lazy<ICrypt>(() => QueryCryptAlgorithm(file), false);

            var dir = new List<Entry>();
            dir_offset = 0;
            using (var header = new BinaryReader(header_stream, Encoding.Unicode))
            using (var filename_map = new FilenameMap())
            {
                Dictionary<string, HxEntry> hx_entry_info = null;
                while (-1 != header.PeekChar())
                {
                    uint entry_signature = header.ReadUInt32();
                    long entry_size = header.ReadInt64();
                    if (entry_size < 0)
                        return null;
                    dir_offset += 12 + entry_size;
                    if (0x656C6946 == entry_signature) // "File"
                    {
                        var entry = new Xp3Entry();
                        while (entry_size > 0)
                        {
                            uint section = header.ReadUInt32();
                            long section_size = header.ReadInt64();
                            entry_size -= 12;
                            if (section_size > entry_size)
                            {
                                // allow "info" sections with wrong size
                                if (section != 0x6f666e69)
                                    break;
                                section_size = entry_size;
                            }
                            entry_size -= section_size;
                            long next_section_pos = header.BaseStream.Position + section_size;
                            switch (section)
                            {
                                case 0x6f666e69: // "info"
                                    if (entry.Size != 0 || !string.IsNullOrEmpty(entry.Name))
                                    {
                                        goto NextEntry; // ambiguous entry, ignore
                                    }
                                    entry.IsEncrypted = 0 != header.ReadUInt32();
                                    long file_size = header.ReadInt64();
                                    long packed_size = header.ReadInt64();
                                    if (file_size >= uint.MaxValue || packed_size > uint.MaxValue || packed_size > file.MaxOffset)
                                    {
                                        goto NextEntry;
                                    }
                                    entry.IsPacked = file_size != packed_size;
                                    entry.Size = (uint)packed_size;
                                    entry.UnpackedSize = (uint)file_size;

                                    if (entry.IsEncrypted || ForceEncryptionQuery)
                                        entry.Cipher = crypt_algorithm.Value;
                                    else
                                        entry.Cipher = NoCryptAlgorithm;

                                    var name = entry.Cipher.ReadName(header);
                                    if (null == name)
                                    {
                                        goto NextEntry;
                                    }
                                    if (entry.Cipher.ObfuscatedIndex && ObfuscatedPathRe.IsMatch(name))
                                    {
                                        goto NextEntry;
                                    }
                                    if (filename_map.Count > 0)
                                        name = filename_map.Get(entry.Hash, name);
                                    if (name.Length > 0x100)
                                    {
                                        goto NextEntry;
                                    }
                                    entry.Name = name;
                                    entry.IsEncrypted = !(entry.Cipher is NoCrypt)
                                        && !(entry.Cipher.StartupTjsNotEncrypted && "startup.tjs" == name);
                                    break;
                                case 0x6d676573: // "segm"
                                    int segment_count = (int)(section_size / 0x1c);
                                    if (segment_count > 0)
                                    {
                                        for (int i = 0; i < segment_count; ++i)
                                        {
                                            bool compressed = 0 != header.ReadInt32();
                                            long segment_offset = base_offset + header.ReadInt64();
                                            long segment_size = header.ReadInt64();
                                            long segment_packed_size = header.ReadInt64();
                                            if (segment_offset > file.MaxOffset || segment_packed_size > file.MaxOffset)
                                            {
                                                goto NextEntry;
                                            }
                                            var segment = new Xp3Segment
                                            {
                                                IsCompressed = compressed,
                                                Offset = segment_offset,
                                                Size = (uint)segment_size,
                                                PackedSize = (uint)segment_packed_size
                                            };
                                            entry.Segments.Add(segment);
                                        }
                                        entry.Offset = entry.Segments.First().Offset;
                                    }
                                    break;
                                case 0x726c6461: // "adlr"
                                    if (4 == section_size)
                                        entry.Hash = header.ReadUInt32();
                                    break;

                                default: // unknown section
                                    break;
                            }
                            header.BaseStream.Position = next_section_pos;
                        }
                        if (!string.IsNullOrEmpty(entry.Name) && entry.Segments.Any())
                        {
                            if (entry.Cipher.ObfuscatedIndex)
                            {
                                DeobfuscateEntry(entry);
                            }
                            if (null != hx_entry_info)
                            {
                                if (hx_entry_info.TryGetValue(entry.Name, out HxEntry info))
                                {
                                    entry.Extra = info;

                                    var sb = new StringBuilder();
                                    if (!string.IsNullOrEmpty(info.Path))
                                    {
                                        sb.Append(info.Path);
                                        if (!info.Path.EndsWith("/") && !info.Path.EndsWith("\\"))
                                            sb.Append('/');
                                    }
                                    if (!string.IsNullOrEmpty(info.Name))
                                    {
                                        sb.Append(info.Name);
                                        if (sb.Length > 0)
                                            entry.Name = sb.ToString();
                                    }
                                    else
                                    {
                                        sb.Append(entry.Name);
                                        if (sb.Length > 0)
                                            entry.Name = sb.ToString();
                                    }
                                }
                            }
                            entry.Type = FormatCatalog.Instance.GetTypeFromName(entry.Name, ContainedFormats);
                            dir.Add(entry);
                        }
                    }
                    else if (0x3A == (entry_signature >> 24)) // "yuz:" || "sen:" || "dls:"
                    {
                        if (entry_size >= 0x10 && crypt_algorithm.Value is SenrenCxCrypt)
                        {
                            long offset = header.ReadInt64() + base_offset;
                            header.ReadUInt32(); // unpacked size
                            uint size = header.ReadUInt32();
                            if (offset > 0 && offset + size <= file.MaxOffset)
                            {
                                var yuz = file.View.ReadBytes(offset, size);
                                var crypt = crypt_algorithm.Value as SenrenCxCrypt;
                                crypt.ReadYuzNames(yuz, filename_map);
                            }
                        }
                    }
                    else if (0x34767848 == entry_signature) // "Hxv4"
                    {
                        if (crypt_algorithm.Value is HxCrypt)
                        {
                            try
                            {
                                var offset = header.ReadInt64() + base_offset;
                                var size = header.ReadUInt32();
                                var flags = header.ReadUInt16();
                                var hx = file.View.ReadBytes(offset, size);
                                var crypt = crypt_algorithm.Value as HxCrypt;
                                hx_entry_info = crypt.ReadIndex(Path.GetFileName(file.Name), hx);
                            }
                            catch (Exception) { /* ignore parse error */ }
                        }
                    }
                    else if (entry_size > 7)
                    {
                        // 0x6E666E68 == entry_signature    // "hnfn"
                        // 0x6C696D73 == entry_signature    // "smil"
                        // 0x46696C65 == entry_signature    // "eliF"
                        // 0x757A7559 == entry_signature    // "Yuzu"
                        uint hash = header.ReadUInt32();
                        int name_size = header.ReadInt16();
                        if (name_size > 0)
                        {
                            entry_size -= 6;
                            if (name_size * 2 <= entry_size)
                            {
                                var filename = new string(header.ReadChars(name_size));
                                filename_map.Add(hash, filename);
                            }
                        }
                    }
                NextEntry:
                    header.BaseStream.Position = dir_offset;
                }
            }
            if (0 == dir.Count)
                return null;

            m_metadata_dict.Clear();
            CxEncryption.m_select_count = 0;

            //foreach(var e in dir)
            //    Console.WriteLine("{0} : {1:X}", e.Name, e.Offset);

            var arc = new ArcFile(file, this, dir);
            try
            {
                if (crypt_algorithm.IsValueCreated)
                    crypt_algorithm.Value.Init(arc);
                return arc;
            }
            catch
            {
                arc.Dispose();
                throw;
            }
        }

        internal static string m_title;
        internal static Dictionary<string, TlgMetaData> m_metadata_dict = new Dictionary<string, TlgMetaData>(StringComparer.OrdinalIgnoreCase);

        public override IImageDecoder OpenImage(ArcFile arc, Entry entry)
        {
            using (var decoder = base.OpenImage(arc, entry))
            {
                var source = decoder.Image.Bitmap;

                try
                {
                    var file_name = Path.GetFileName(entry.Name);
                    if (!m_metadata_dict.ContainsKey(file_name))
                    {
                        ReadMetaData(arc, entry.Name.ToLower());
                        if (!m_metadata_dict.ContainsKey(file_name))
                            return decoder;
                    }

                    int byte_depth;
                    int stride;
                    byte[] pixels;
                    int offset;

                    var meta = m_metadata_dict[file_name];
                    if (meta.BaseName == null)
                    {
                        if (
                            (meta.BaseWidth != 0 && meta.BaseHeight != 0) &&
                            (meta.Width != meta.BaseWidth || meta.Height != meta.BaseHeight)
                            )
                        {
                            byte_depth = meta.BPP / 8;
                            stride = meta.iBaseWidth * byte_depth;
                            pixels = new byte[stride * meta.BaseHeight];
                        }
                        else
                            return decoder;
                    }
                    else
                    {
                        var base_name = Path.GetDirectoryName(entry.Name) + meta.BaseName;
                        var base_entry = arc.Dir.FirstOrDefault(e => e.Name.ToLower() == base_name);
                        if (base_entry == null)
                            return decoder;

                        using (var input = arc.OpenImage(base_entry))
                        {
                            meta.iBaseWidth = input.Image.Bitmap.PixelWidth;
                            meta.iBaseHeight = input.Image.Bitmap.PixelHeight;

                            byte_depth = meta.BPP / 8;
                            stride = meta.iBaseWidth * byte_depth;
                            pixels = new byte[stride * meta.BaseHeight];

                            input.Image.Bitmap.CopyPixels(Int32Rect.Empty, pixels, stride, 0);
                        }
                    }

                    Int32Rect rect = new Int32Rect(0, 0, meta.iWidth, meta.iHeight);
                    var offsset_x = meta.OffsetX;
                    var offsset_y = meta.OffsetY;
                    if (offsset_x < 0)
                    {
                        rect.X = -meta.OffsetX;
                        if (meta.Width + meta.OffsetX > meta.BaseWidth)
                            rect.Width = meta.iBaseWidth;
                        else
                            rect.Width = meta.iWidth;
                        offsset_x = 0;
                    }
                    if (offsset_y < 0)
                    {
                        rect.Y = -meta.OffsetY;
                        if (meta.Height + meta.OffsetY > meta.BaseHeight)
                            rect.Height = meta.iBaseHeight;
                        else
                            rect.Height = meta.iHeight;
                        offsset_y = 0;
                    }
                    offset = offsset_y * stride + offsset_x * byte_depth;

                    m_metadata_dict[file_name] = meta;

                    source.CopyPixels(rect, pixels, stride, offset);
                    source = BitmapImage.Create(
                        meta.iBaseWidth,
                        meta.iBaseHeight,
                        ImageData.DefaultDpiX,
                        ImageData.DefaultDpiY,
                        source.Format,
                        source.Palette,
                        pixels,
                        stride
                        );
                }
                catch (Exception e)
                {
                    Console.WriteLine(entry.Name);
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                }

                return new BitmapSourceDecoder(source);
            }
        }

        private void ReadMetaData(ArcFile arc, string name)
        {
            var v1_title = new List<string>()
            {
                //ハイクオソフト
                "面影レイルバック",
                "幼なじみとの暮らし方出張版　プロポーズ作戦",
                //Lose
                "ものべの -happy end-"
            };
            var v2_title = new List<string>()
            {
                //HULOTTE
                "妹のおかげでモテすぎてヤバい。",
                "叶とメグリとのその後がイチャらぶすぎてヤバい。",
                "嫁探しが捗りすぎてヤバい。",
                "神頼みしすぎて俺の未来がヤバい。",
                "出会って5分は俺のもの! 時間停止と不可避な運命",
                "俺の姿が、透明に!? 不可視の薬と数奇な運命",
                "俺の恋天使がポンコツすぎてコワ～い。",
                "俺の瞳で丸裸! 不可知な未来と視透かす運命",
                //HULOTTE Roi
                "ココロのカタチとイロとオト",
                //あざらしそふと+1
                "夢幻のティル・ナ・ノーグ", 
                //Mint CUBE
                "あま恋シロップス",
                "人気声優のつくりかた",
                "勇者と魔王と、魔女のカフェ",
                //CUBE
                "your diary+H",
                "恋する彼女の不器用な舞台",
                "間宮くんちの五つ子事情",
                "ゆらめく心に満ちた世界で、君の夢と欲望は叶うか",
                "神様のような君へ",
                "海と雪のシアンブルー",
                "神様のような君へ EXTENDED EDITION", //鍵無し
                "ネコと女子寮せよ！",
                "夏ノ終熄",
                "サメと生きる七日間",
                "恋し彩る正義爛漫",
                //Clover GAME
                "すれ違う兄妹の壊れる倫理観",
                "メイドちゃんは迷途ちゅう",
            };

            if (v1_title.Contains(Xp3Opener.m_title))
                ReadMetaV1(arc, name);
            else if (v2_title.Contains(Xp3Opener.m_title))
                ReadMetaV2(arc, name);
        }

        //ハイクオソフト, Lose
        private void ReadMetaV1(ArcFile arc, string name)
        {
            var name_parts = name.Split('_');
            string meta_name = name_parts[0];
            for (int i = 1; i < name_parts.Length - 1; ++i)
                meta_name += '_' + name_parts[i];
            meta_name += ".txt";

            var entry = arc.Dir.FirstOrDefault(e => e.Name.ToLower() == meta_name);
            if (entry == null)
                return;

            using (var input = arc.OpenEntry(entry))
            {
                Encoding encoding;
                if (input.ReadByte() == 0x23 && input.ReadByte() == 0x00) //'#'
                    encoding = Encoding.Unicode;
                else
                    encoding = Encoding.GetEncoding(932);
                var reader = new StreamReader(input, encoding, false, 0x10000, false);
                var key_list = reader.ReadLine().Split('\t');

                var base_dict = new Dictionary<string, string>();
                var line = reader.ReadLine().Split('\t');
                foreach (var item in key_list.Zip(line, (key, value) => new { key, value }))
                    base_dict.Add(item.key, item.value);

                while (!reader.EndOfStream)
                {
                    Dictionary<string, string> meta_dict = new Dictionary<string, string>();
                    line = reader.ReadLine().Split('\t');
                    foreach (var item in key_list.Zip(line, (key, value) => new { key, value }))
                        meta_dict.Add(item.key, item.value);

                    try
                    {
                        m_metadata_dict.Add(
                            Path.GetFileNameWithoutExtension(meta_name) + '_' + meta_dict["layer_id"] + Path.GetExtension(name),
                            new TlgMetaData
                            {
                                BaseName = null,
                                OffsetX = int.Parse(meta_dict["left"]),
                                OffsetY = int.Parse(meta_dict["top"]),
                                Width = uint.Parse(meta_dict["width"]),
                                Height = uint.Parse(meta_dict["height"]),
                                BaseWidth = uint.Parse(base_dict["width"]),
                                BaseHeight = uint.Parse(base_dict["height"]),
                                BPP = 32
                            });
                    }
                    catch { }
                }
            }
        }

        //HULOTTE, あざらしそふと+1, CUBE, Mint CUBE
        private void ReadMetaV2(ArcFile arc, string name)
        {
            string meta_name;
            if (Path.GetFileName(name).Substring(0, 3) == "ev_")
                meta_name = name.Substring(0, 6);
            else
                meta_name = name.Substring(0, 4);

            if (name.Contains('l' + Path.GetExtension(name)))
                meta_name += "l.csv";
            else
                meta_name += ".csv";

            var meta_entry = arc.Dir.FirstOrDefault(e => e.Name.ToLower() == meta_name.ToLower());
            if (meta_entry == null)
                return;

            using (var input = arc.OpenEntry(meta_entry))
            {
                var reader = new StreamReader(input, Encoding.GetEncoding(932), false, 0x10000, false);
                var key_list = reader.ReadLine().Split(',');

                while (!reader.EndOfStream)
                {
                    var meta_dict = new Dictionary<string, string>();
                    var line = reader.ReadLine().Split(',');
                    foreach (var item in key_list.Zip(line, (key, value) => new { key, value }))
                        meta_dict.Add(item.key, item.value);
                    if (meta_dict["tag"] == meta_dict["base"])
                        continue;

                    try
                    {
                        m_metadata_dict.Add(
                            meta_dict["tag"].ToLower() + Path.GetExtension(name),
                            new TlgMetaData
                            {
                                BaseName = meta_dict["base"].ToLower() + Path.GetExtension(name),
                                OffsetX = int.Parse(meta_dict["x"]),
                                OffsetY = int.Parse(meta_dict["y"]),
                                Width = uint.Parse(meta_dict["w"]),
                                Height = uint.Parse(meta_dict["h"]),
                                BPP = 32
                            });
                    }
                    catch { }
                }
            }
        }

        static readonly Regex ObfuscatedPathRe = new Regex(@"[^\\/]+[\\/]\.\.[\\/]");

        private static void DeobfuscateEntry(Xp3Entry entry)
        {
            if (entry.Segments.Count > 1)
                entry.Segments.RemoveRange(1, entry.Segments.Count - 1);
            entry.IsPacked = entry.Segments[0].IsCompressed;
            entry.Size = entry.Segments[0].PackedSize;
            entry.UnpackedSize = entry.Segments[0].Size;
        }

        internal static long SkipExeHeader(ArcView file, byte[] signature)
        {
            var exe = new ExeFile(file);
            if (exe.ContainsSection(".rsrc"))
            {
                var offset = exe.FindString(exe.Sections[".rsrc"], signature);
                if (offset != -1 && 0 != file.View.ReadUInt32(offset + signature.Length))
                    return offset;
            }
            var section = exe.Overlay;
            while (section.Offset < file.MaxOffset)
            {
                var offset = exe.FindString(section, signature, 0x10);
                if (-1 == offset)
                    break;
                if (0 != file.View.ReadUInt32(offset + signature.Length))
                    return offset;
                section.Offset = offset + 0x10;
                section.Size = (uint)(file.MaxOffset - section.Offset);
            }
            return 0;
        }

        public override Stream OpenEntry(ArcFile arc, Entry entry)
        {
            var xp3_entry = entry as Xp3Entry;
            if (null == xp3_entry)
                return arc.File.CreateStream(entry.Offset, entry.Size);

            Stream input;
            if (1 == xp3_entry.Segments.Count && !xp3_entry.IsEncrypted)
            {
                var segment = xp3_entry.Segments.First();
                if (segment.IsCompressed)
                    input = new ZLibStream(arc.File.CreateStream(segment.Offset, segment.PackedSize),
                                            CompressionMode.Decompress);
                else
                    input = arc.File.CreateStream(segment.Offset, segment.Size);
            }
            else
                input = new Xp3Stream(arc.File, xp3_entry);

            return xp3_entry.Cipher.EntryReadFilter(xp3_entry, input);
        }

        public override ResourceOptions GetDefaultOptions()
        {
            return new Xp3Options
            {
                Version = Properties.Settings.Default.XP3Version,
                Scheme = GetScheme(Properties.Settings.Default.XP3Scheme),
                CompressIndex = Properties.Settings.Default.XP3CompressHeader,
                CompressContents = Properties.Settings.Default.XP3CompressContents,
                RetainDirs = Properties.Settings.Default.XP3RetainStructure,
            };
        }

        public override object GetCreationWidget()
        {
            return new GUI.CreateXP3Widget();
        }

        public override object GetAccessWidget()
        {
            return new GUI.WidgetXP3();
        }

        ICrypt QueryCryptAlgorithm(ArcView file)
        {
            /*var alg = GuessCryptAlgorithm(file);
            if (null != alg)
                return alg;
            var options = Query<Xp3Options>(arcStrings.XP3EncryptedNotice);
            m_title = new WidgetXP3().Scheme.SelectedValue as string;

            return options.Scheme;*/
            return new CxEncryption(new CxScheme
            {
                Mask = 0x000002B4,
                Offset = 0x0000013E,
                PrologOrder = new byte[] { },
                OddBranchOrder = new byte[] { },
                EvenBranchOrder = new byte[] { },
                ControlBlock = new uint[] { 0x27967CC4, 0xF699B302, 0xD84FED37, 0xE19AD646, 0x0C03DA12, 0x4FD1C841, 0x4305B846, 0x3931D01F, 0xE92A7768, 0x74702288, 0x801B4123, 0x0101A811, 0x42A1B3C1, 0xB70185B0, 0xC2BC0179, 0x7DFB3FDD, 0xECB80423, 0x9B59E197, 0x05D92968, 0xC0648D6D, 0xBD3E0E2F, 0x64F29A26, 0xB428403C, 0x72D1BF0D, 0x5B924AE2, 0x99495123, 0xFF61A665, 0x7AC710EA, 0xBC5CC2B4, 0xF233305A, 0x2079E375, 0x44CA9B7F, 0x7CA2A817, 0x9EBC994F, 0x5F13FD6C, 0x45EB7E99, 0x04D41767, 0x4D498F79, 0x99699CBD, 0xA8972C96, 0xA1BF5FEF, 0x8F66C776, 0x41300B07, 0x752F5D69, 0x559BC0B2, 0x5DE01395, 0x7A8D62AF, 0xA45F45B0, 0x31AA2FDB, 0xAC598AFE, 0x812DF763, 0x04E90E74, 0x8EE92DA0, 0x5FCFDBE0, 0xC3892139, 0xAAB07B28, 0x75BFF00C, 0x1B26E7C1, 0x88CB4820, 0xD3831E89, 0xDD0FC253, 0x45C9DA66, 0x48B1BA85, 0x9F521ADF, 0x899443B8, 0x3CE75506, 0x6F8114F1, 0x7B31F7C9, 0xE4F279ED, 0xA52787A4, 0x6C93EE4D, 0x7D2EA3E2, 0x1B236AFE, 0x1E4F8BEA, 0x27E61A46, 0x796F5931, 0x1B6E0779, 0x57DDA073, 0x7F8BDB68, 0xA1161FE2, 0x4148BEB5, 0x97231734, 0x83795B50, 0x4843023C, 0x905E3230, 0xAC096A75, 0x8A252C01, 0xC410D988, 0x190D1FC7, 0xFE532E2D, 0x455C66A1, 0x8B9A9CA1, 0x992B771F, 0x793CE8BB, 0x1933A95F, 0x547E58DC, 0xCF9BF0A5, 0xD05BC1B4, 0x8E45A04C, 0x41D4DB8F, 0xBE46206A, 0x557DB111, 0x5DDA60C4, 0x30CBB2F1, 0xA636A70C, 0x29365247, 0xB36DC0BE, 0x20C43001, 0x4F98EB67, 0x31CDEF2D, 0x1407BF22, 0x5152DE1D, 0xB3B39646, 0x2C381524, 0xF7A0F391, 0xC5B6A703, 0xB43840FB, 0xDDD54A70, 0x14E4A018, 0x2A4E030D, 0x6514994F, 0x64D1769D, 0xBDABBE05, 0x242BEEDB, 0x678236D0, 0x17DC915C, 0x6E0F7E34, 0xA9AEF327, 0xCC20C682, 0x21B9959A, 0xF4EF972F, 0x2A5DC25B, 0x4B3B53C3, 0xA6E1BE54, 0x4B3682E0, 0xCBEB0CBB, 0x9796BABE, 0xF069BD48, 0x7D8193DC, 0x9C852E6F, 0xE73C04F5, 0x2E62B2FE, 0xAA41A7FE, 0xE48C88A4, 0x7C6118AC, 0xC85E108A, 0x44F56A48, 0xB4C9D351, 0x70127E1A, 0xCA1FDAA1, 0x9C334809, 0x8C7C1C26, 0xF42F0899, 0xB3305A91, 0xC79C68DA, 0xCE414FF9, 0x89DE8275, 0xE7160F76, 0xF662A765, 0x709F87D5, 0xBC6F29BE, 0x9B5635B6, 0x1E45D120, 0xD1D789B3, 0xB37ACDF0, 0xE55CBCB5, 0x0374239D, 0x50173056, 0x1F5BFDA2, 0xA944B27F, 0x5857EE15, 0x71E7EA9F, 0xDE5D6BF7, 0x447D9CC0, 0x2908171F, 0x3AAFAF66, 0x81462BD6, 0x202DCC18, 0x0816DC96, 0x9397C5D9, 0x79A47D20, 0xC8E0F91F, 0x22BC6621, 0x257A8615, 0xCDAC1CE0, 0xCAF8B52C, 0x6C86DD65, 0x84D5169C, 0x4DB10EAC, 0x510D435E, 0xAAD57C70, 0xF7B4A31C, 0xCA73B3AE, 0x3192C1E5, 0xA68805E5, 0x8CAA9D48, 0xD7CC26C9, 0xAA4760E9, 0xA1E3B54F, 0x836C23E0, 0x8076A73B, 0x5E7A2DA6, 0xBBC342F7, 0xF3F2057D, 0x02F40624, 0xE2E30D03, 0x132DAF83, 0x5B796EF3, 0xEA32ACDF, 0x1742AB5B, 0xCD906F6B, 0x3C3731AB, 0x0CD9B822, 0xE3EF1BFC, 0xC38A4DB8, 0x69FABA2E, 0x3CCCD2A1, 0x2F06FE0B, 0xAB619D4D, 0x27ADC3CC, 0x1E2B67EE, 0x5880E707, 0x400B7B42, 0x7C11C2CF, 0x6F3BD935, 0xA0715F72, 0xF5E11622, 0xC5DAF675, 0xEE27CF9D, 0x4C475001, 0x44E1FCCB, 0xFD970672, 0x9F6421D0, 0x15052704, 0x65B5B5F4, 0x225A0A4F, 0xF808EDA0, 0x610A8E8B, 0xF20B0666, 0xD1BD74F2, 0x05204ADC, 0xB60A98C6, 0xA042FE28, 0x6CB880C0, 0xBD04F5BC, 0x533FFD97, 0x7DFF1D36, 0x0512C16F, 0x0BC2BF6A, 0xB8F2E47E, 0xB49932AD, 0x43AE6044, 0x3132B568, 0xFCD74852, 0x1C5FA5C7, 0x89FE4452, 0xB926BA1B, 0x62453AA5, 0x24A5237C, 0x1BEDD11B, 0x298B6AB0, 0x6B12C438, 0x7C562A96, 0x7DBBECAD, 0xA80E1346, 0xC79D32E9, 0xA48C308A, 0x3421B1CA, 0xE3C138D4, 0x95A34D6F, 0x9CCB8117, 0x8FE586CF, 0x2EAF4678, 0x9C8C27AA, 0xD817BCF6, 0x271C2A49, 0x23F0C3E8, 0x5EF8D876, 0xBBCD7E6D, 0x59031BF7, 0x331D0896, 0xB452B0DB, 0x6B7C5E5B, 0x1CBE3970, 0x5E11DBA5, 0x8637160C, 0x24ED640E, 0x43C23E6D, 0x2093FB7E, 0xDDA62322, 0x9DAD9F47, 0xB67C8724, 0xF36F03AB, 0x2017931B, 0xD80EA453, 0xA08CFF25, 0x70DFFF0F, 0xDA71D142, 0x2E25F344, 0x869120CD, 0xD39BA29D, 0x29933D33, 0xB260229F, 0xAE7A0984, 0xF736E1DC, 0xF2B42BA2, 0x4B3F2B2A, 0x8F3C494D, 0xC4CA50F0, 0x0774D386, 0xB576D584, 0x074750FA, 0x376DE0CB, 0xC45DE1C0, 0x2EA656BA, 0x4ED261CA, 0x726EF56C, 0x6D266EAD, 0x0DD27B5C, 0x6AEED8D4, 0x8B1FE49A, 0xEB15D35E, 0x4E0E17A8, 0x9E3C1E3F, 0x8B7F82DA, 0x7DE56BE6, 0x44F22F4B, 0x43B8743B, 0x6609B21C, 0xBF02A7FA, 0x8C3C4197, 0x8BA22298, 0xA8C192E8, 0xF43A7904, 0x8BE3731B, 0x210696E7, 0x2B7D63A0, 0x6998B44A, 0x568E5346, 0xBDE8F12B, 0xBD69D9DA, 0x65E40631, 0xC80C6F11, 0x584D87ED, 0xA6AA15B5, 0xE37A1936, 0x8B6C3324, 0xCB314609, 0x1F7EC282, 0x01FEA498, 0x51EBE358, 0x4C48DD32, 0x76530C66, 0x78BA478B, 0x3A45457B, 0x0BBD0F95, 0xA358CA57, 0x34C83528, 0x84144C7F, 0x4D8AD7EC, 0xB5C64BA8, 0x9C4B347E, 0x38E4BB4C, 0xDFDADA48, 0x87403990, 0xE02AE5CE, 0x29941AF8, 0x5922C81B, 0xB37CDAA8, 0xCF8FB919, 0x72115ACC, 0xA67D7F22, 0x94A83F38, 0xF4D8B53E, 0x0890C79B, 0x821208DD, 0xB03ED99A, 0x883C27FB, 0x04F87C88, 0x0ADD7A26, 0x34F27585, 0x85F40425, 0xB622A56E, 0xF45F3E5F, 0xCBB0D953, 0xDE2F5FD0, 0xFA3F464D, 0x6FAAD5B9, 0xF313E17D, 0xCE9C02D8, 0x64E0361D, 0x33CD2E9A, 0xB70B4081, 0xD02583CA, 0xBFEC0C57, 0x90D71087, 0xB7CFD035, 0xA369E26C, 0x4C93EB0E, 0x39D6BAD7, 0xE591645A, 0xA2452EBA, 0xC9946E2D, 0x1F92652E, 0x1EB1C9E7, 0xA4A4C0B5, 0x588FFB10, 0x40A46E70, 0x5E06CE4D, 0xBEB8D403, 0xD4D25B16, 0x68218612, 0xDFB2685C, 0xEA473F41, 0x29F6D86D, 0x735E1F8B, 0x6AB6ADF9, 0x3DC8D93D, 0xC4DF2E60, 0xE99BDF5B, 0x10FD429F, 0x8BAF86D1, 0xFF4841F5, 0x0B324A64, 0xF0E77AE6, 0xA786EE77, 0x59E8A54B, 0xDF82C0E3, 0xA16BE0CF, 0xBF0B98A3, 0x42EE17A9, 0xDF475731, 0xC837D02F, 0x288C11CA, 0x87BCEBCA, 0x230EBBCB, 0x961C84E3, 0xA3C89A85, 0x7A420169, 0x8187DCD1, 0x79FB4F9C, 0x8C587A69, 0x2832CCA9, 0x59BF3E86, 0x71F35B38, 0x7D86DB29, 0x54373BB9, 0x21C86DA3, 0xEC936EC4, 0x478EA653, 0xE006BA04, 0x160289F4, 0xBD3AA45B, 0x50E918AE, 0xC3C2DB10, 0x601B2529, 0x63B632D3, 0x67B24C62, 0x7A9FA14B, 0x15542997, 0xA0B0028C, 0xE6A70CC6, 0x4E56459B, 0xBD62E4E4, 0xF2E17E6E, 0xC5F214B9, 0x13ECFD18, 0x832D457A, 0xF4759655, 0xB17139B5, 0x80122D5C, 0x2E3E0F62, 0x637E4D63, 0x15C51145, 0xB50F044B, 0x86F1D19C, 0xD2F30564, 0x51CC2B9A, 0x4C5D077C, 0x6F8080DD, 0x1E671133, 0xFA80B4BD, 0xC94D4292, 0x61C237C1, 0xBE2271EC, 0xEB8578FB, 0x3F4F303E, 0x9852ACE6, 0x33054FA4, 0x413FCE16, 0xF5D792D8, 0xB10D0DA4, 0x0C54B37C, 0x83908B20, 0x9E174165, 0x0A1422B6, 0xF73E5B02, 0x701D7009, 0x2BEE9183, 0x25FF3E7D, 0xB774B360, 0x8C5B68A1, 0xEF9EBBEE, 0x499C1AE1, 0x860E06D7, 0x8BC2921F, 0x025C7F59, 0x22E7A958, 0x954DB5B7, 0x0A723D92, 0x117C355C, 0xF99E39F6, 0x5EC11F41, 0x93A61E77, 0x0F928B48, 0xE39E0E31, 0x83122D23, 0x2685BD2B, 0x7337E9CA, 0x6C4C7D60, 0x66BB3D67, 0x4DEC4FB3, 0x6007D1E8, 0x4CF79B14, 0xBB80919C, 0x65220E7C, 0x5F855C62, 0xC305865A, 0x861846BF, 0x5AA79BFC, 0xC11355CB, 0x8A53BC59, 0xDB4AE566, 0x8223F870, 0xFFDC8A20, 0xC0406D5C, 0x1725BBEA, 0xF2F60EC0, 0x581395D2, 0x5B58DD5B, 0xD5B0BCFD, 0x888E875C, 0x0D22260A, 0x1E8051BA, 0x61239C0E, 0x2B45F601, 0xFD4D8B6E, 0x72A3E690, 0x2DFF92BB, 0x8A35DD1C, 0x156C86CD, 0xB920D48B, 0xA4D1B7D7, 0x7ABD65B4, 0x99E775B0, 0x7653503F, 0xC615A37A, 0xCD7AF7CB, 0xCEEE348D, 0x42DBFA3E, 0x7C68FCAB, 0x910BADEA, 0xDC644AA5, 0xF4F141DA, 0x49298A77, 0x8B14C421, 0x8DD8693A, 0x78927738, 0xE56BC741, 0x2FE14083, 0xBA74EF88, 0x7BCB080B, 0xFEBE7EAA, 0xB91DCEF6, 0xC7ABBE1B, 0x474CF70B, 0x102BDECC, 0x1AC30C7E, 0x38455C67, 0xB3F0F218, 0xF4C07DC7, 0x9A1A3FB6, 0x87F5266F, 0x45894587, 0x4F40BE78, 0xAB88BD23, 0x3149974D, 0x417457A2, 0x0E447148, 0xBEBB2841, 0x2D061860, 0x5A0C8CBD, 0xE52E4D23, 0x45AF03EB, 0xC02B4B27, 0x8E293C30, 0xF34FA442, 0x15B6FDFD, 0x2F2BD584, 0xAEA0E423, 0x1B32928A, 0xD987A108, 0x2EC2C976, 0x4B2588FB, 0x73BE5A85, 0x03727CB7, 0xAFC68FAB, 0x959B6AA8, 0xA05690B3, 0x5F325BCE, 0x6805D616, 0xAC4431A6, 0x0DD79062, 0xBD4631F1, 0x3C6D03DE, 0x45C3A40F, 0xBB4C111F, 0xBBD0E50E, 0xDBF542EF, 0x8BA6B4CA, 0x5EE36C9B, 0xA11A187C, 0xF26AD07A, 0x26F8DBB8, 0x75442366, 0x6DCCDCEA, 0xA4C9662F, 0x337F342B, 0x2CD80617, 0x40B9608E, 0x75D31039, 0x9E710988, 0x6340EEE5, 0xF8908F1C, 0xC810D674, 0xEFDD1510, 0x293094E7, 0xD2F5919A, 0x858C0589, 0x167E28C2, 0xB5C3D446, 0x39028E0A, 0xF187025F, 0xE5B1C2D5, 0xD76455CC, 0xCC97A521, 0x224896EF, 0xFEFE0782, 0xF07603BD, 0x5FDBD51A, 0xF4F45CD4, 0x9824537F, 0xF6AAE07B, 0x216B274F, 0x6F77370B, 0xE5ABE945, 0xB783209B, 0x356CC40F, 0xDD1BB992, 0x633B8DA6, 0xAB840772, 0x89CDC917, 0x51A32CCA, 0xD9250E70, 0x401C1A3E, 0x0BA9868B, 0xACD34B3B, 0xE7EFE082, 0x5AE8680E, 0x7459333D, 0x14568C48, 0xA67C5BBC, 0xEB32022D, 0xD0C15156, 0xF6970EB9, 0xA98A99A3, 0xF576C6D1, 0x782DC642, 0xF05F68F5, 0x1D6361A5, 0x94862B02, 0x53F52B03, 0xDC5C2ACA, 0x9338DCC9, 0xA1C91AA7, 0xD565B816, 0x17F6FA04, 0xA7AB5273, 0xC70235B9, 0x66CE8443, 0xE275896E, 0x1E55E7BE, 0x89933004, 0xC2C7C578, 0x44FBF54A, 0xE3ED02F0, 0x3389FCD6, 0x8C3E40C5, 0x61E9A375, 0x5E46CE69, 0x82918DE7, 0x45E7A866, 0xA3F71B9F, 0xF224C00E, 0xB6B30E50, 0x8601BA74, 0x42481379, 0xFEA7C676, 0x6C94BC95, 0x34E4C007, 0x9ED40B66, 0x1C53E1C3, 0x9276103E, 0xB902A0CC, 0x1F396F2F, 0xB932C723, 0x6C556C58, 0xA2A79BCF, 0x645710C3, 0x57DFDCFE, 0x893B5223, 0x0F60E751, 0xA9373750, 0xAA6184DC, 0xBA4DC401, 0x11DB2A26, 0x19772CA1, 0x2C51404C, 0xAEF223D3, 0x8D8B7092, 0xF823F678, 0x4AAD8A1F, 0xC6C2E763, 0x7A72E83A, 0xCCFD62B7, 0x2124C52A, 0x940A0A8C, 0x32A97D92, 0xB6CDC02D, 0x552A81DA, 0xEA5AF9CC, 0x81767103, 0x4D1FF35A, 0x82C0FB47, 0xEB934B3C, 0x9CA5E297, 0xD1A263F0, 0xD483030C, 0xF2A13614, 0x11BF4C43, 0x9DA510A5, 0x55F42011, 0x8EEEB03F, 0xC55F16D1, 0xA58A7B31, 0x77FBF623, 0x9D1CEA16, 0x0BC176BE, 0xA47831B8, 0x30F4A738, 0x0AC9953A, 0xD2C57809, 0x6FAC23BC, 0xD60982DF, 0x21AA1E8C, 0x0A79EC84, 0x4F524AE9, 0xEA44B82C, 0x1D359A95, 0xE538322B, 0xA7BCCEAF, 0xC6056353, 0x37D4D325, 0xF940A7E1, 0x9619CED5, 0x08AE42F6, 0x85084EDB, 0xB8F796C4, 0x0E3E7187, 0xDD757B37, 0x72B7E813, 0x28212093, 0xF5FC7C26, 0x93CCCA37, 0x49E3BB20, 0x7C24BD51, 0xD1EE878F, 0x2F503FDF, 0xB1DDF262, 0x6A8EB8B7, 0xD673FD92, 0xFDECC2A7, 0xE8CD68AB, 0xB96CD59B, 0x72E44241, 0xA10F75CB, 0x73EC6E16, 0x8007D971, 0x089B52DE, 0x0511596B, 0xA1F4DE50, 0x35FF0213, 0xD5C3CAE4, 0xADDB1CB0, 0x97302472, 0x557B7AFD, 0x0FADFDF4, 0x97731FB3, 0xCC734F75, 0xE2520B7E, 0x3389C715, 0x73682F4E, 0x04227A72, 0xE301D3C5, 0x0E939B4F, 0xB1F0B55E, 0x3E8B561E, 0x7BFC6093, 0xCC218722, 0xACED4541, 0xBAF4A3B3, 0xAE0C5761, 0xAA279FFB, 0x7DDEDC5A, 0xEAD6F8D1, 0xD71B1ED3, 0xC8FA6722, 0x193C298A, 0x4D669BA9, 0x654CF8EA, 0xC0A3E957, 0x8F6171F1, 0xB37A429C, 0x3356E508, 0x5C5CF847, 0x279B4684, 0xE403BC73, 0x43E1ABAA, 0x20989091, 0x5CE53871, 0x3D11B157, 0xC6DDD174, 0x3B6DB475, 0xB09F28F8, 0x50E27863, 0x05A72956, 0x10692301, 0xF7B3C22F, 0x98E0600A, 0xD404484E, 0x280164D7, 0x36AAD704, 0xF34FF611, 0x697DFB88, 0xDAF3FE82, 0xF22B6438, 0xBE9B8445, 0x3DB42ED5, 0xF8F5D90F, 0x4F8A3597, 0x4FDCAD38, 0xECC48918, 0x55CD3A37, 0x05DA2AAE, 0xB3FF20D1, 0x3301EBCA, 0x36BAEA38, 0xB44D4017, 0x8F0AFBFD, 0x789996D7, 0xAA591865, 0x36822868, 0xD21AEC74, 0xD1D2CE09, 0x8871788F, 0xFB71BC9D, 0x0F4E64A4, 0x65C67C13, 0x79C37E77, 0xAF0C7B6D, 0x91CA69CA, 0xC043C543, 0x3BD985C4, 0xDC0F8F51, 0x514960FA, 0x1B0829B2, 0x790967C3, 0x1F6A26B7, 0x7CF7D0D8, 0x7F56213F, 0x95DC10B6, 0x2DF17D59, 0x2633ADB6, 0x35E4EAFA, 0x9F849224, 0x6E64C429, 0x070AF736, 0x49349A4A, 0xD20B71FE, 0x0FB03261, 0x6DA7D5EB, 0xB0B38FCD, 0x7D3E0BE5, 0xA0CAF53D, 0xC82509E0, 0xAA69534D, 0x2039F5DC, 0x9848BB2A, 0x73B89899, 0x9B5ED474, 0x4179C7FB, 0x20CFEDFB, 0xD6B019BB, 0x8C632D02, 0x178259F9, 0x877C5F54, 0xC2A8BD37, 0x38701E68, 0xA5013209, 0xCAA739D4, 0x3C4C104C, 0x74BC22AE, 0xA4471920, 0x2AC72A18, 0x96AB89B9, 0x136FF001, 0x0FEB5297, 0x34943C89, 0x1FCB2F45, 0x79071BB6, 0x7B251348, 0xB3A9C7F2, 0x0EC4F6E6, 0x7D5A0B40, 0x7307E649, 0xBC294C07, 0x2FD39403, 0x6ABBCB67, 0x4B76CC60, 0x4793F2AE, 0xD57CED5E, 0x02CE3C42, 0x9671A7BA, 0xDC5D235A, 0x77A35BA9, 0x3872F338, 0xBB9959E0, 0x9C97E066, 0xC729C8F8, 0xF3FEB1B1, 0x3C2A529B, 0x4864B25D, 0xEDF716C9, 0x7B88A88F, 0xA2837EF2, 0x9B7A9810, 0x7048F75C, 0x410F482A, 0xCE971236, 0x853D4F68, 0xF16F2CA2, 0x66A55CFA, 0xAA022AD3, 0x4CF9A3AF, 0x455F2D0A, 0x2605858D, 0x0D70331A, 0x5147880D, 0x75048BE2, 0xF6C9C51F, 0xC62D0980, 0xB55FABB7, 0x68E69C8F, 0xD150AD7C, 0xF5406BF9, 0x8979F08F, 0x03A990EC, 0x0430B622, 0x3B34D931, 0x4A871D59, 0xD2B94713, 0xB1D4A8AF, 0x77F27DF3, 0xB8A5110C, 0x2C31C1D0, 0xC11E910E, 0x67EC2F31, 0x34C0A3ED, 0x41C98E9F, 0x9920D9EF, 0xEF17FB4C, 0x25D1DEE9, 0xF3747244, 0xFFFB4546, 0x3CFA67DB, 0x5BDFE150, 0x871F2F80, 0x3F4FF9E5, 0x4E8B3989, 0x3555F55C, 0x336C631D, 0x3B5130D4, 0xCBCE0CD8, 0x61B79F07, 0x9F718B4E, 0x897ECFF2, 0x778A259D, 0x19F81898, 0x491A20E9, 0x6C2B4445, 0xA53D579A, 0xD1B180AD, 0xDCE5F662, 0x7A5246CC, 0xC65FC753, 0x5EE08CE6, 0xB4E177E5, 0x149B1D5E, 0x70038BC0, 0x827102A0, 0x61275503, 0x6F5DCB35, 0xE97888A0, 0xC0C4359D },
                TpmFileName = null
            });
        }

        public static ICrypt GetScheme(string scheme)
        {
            ICrypt algorithm;
            if (string.IsNullOrEmpty(scheme) || !KnownSchemes.TryGetValue(scheme, out algorithm))
                algorithm = NoCryptAlgorithm;
            return algorithm;
        }

        static uint GetFileCheckSum(Stream src)
        {
            // compute file checksum via adler32.
            // src's file pointer should be reset to zero.
            var sum = new Adler32();
            byte[] buf = new byte[64 * 1024];
            for (; ; )
            {
                int read = src.Read(buf, 0, buf.Length);
                if (0 == read) break;
                sum.Update(buf, 0, read);
            }
            return sum.Value;
        }

        public override void Create(Stream output, IEnumerable<Entry> list, ResourceOptions options,
                                     EntryCallback callback)
        {
            var xp3_options = GetOptions<Xp3Options>(options);

            ICrypt scheme = xp3_options.Scheme;
            bool compress_index = xp3_options.CompressIndex;
            bool compress_contents = xp3_options.CompressContents;
            bool retain_dirs = xp3_options.RetainDirs;

            bool use_encryption = !(scheme is NoCrypt);

            using (var writer = new BinaryWriter(output, Encoding.ASCII, true))
            {
                writer.Write(s_xp3_header);
                if (2 == xp3_options.Version || 3 == xp3_options.Version)
                {
                    writer.Write((long)0x17);
                    writer.Write((int)1);
                    writer.Write((byte)0x80);
                    writer.Write((long)0);
                }
                long index_pos_offset = writer.BaseStream.Position;
                writer.BaseStream.Seek(8, SeekOrigin.Current);

                int callback_count = 0;
                var used_names = new HashSet<string>();
                var dir = new List<Xp3Entry>();
                long current_offset = writer.BaseStream.Position;
                foreach (var entry in list)
                {
                    if (null != callback)
                        callback(callback_count++, entry, arcStrings.MsgAddingFile);

                    string name = entry.Name;
                    if (!retain_dirs)
                        name = Path.GetFileName(name);
                    else
                        name = name.Replace(@"\", "/");
                    if (!used_names.Add(name))
                    {
                        Trace.WriteLine("duplicate name", entry.Name);
                        continue;
                    }

                    var xp3entry = new Xp3Entry
                    {
                        Name = name,
                        Cipher = scheme,
                        IsEncrypted = use_encryption
                                       && !(scheme.StartupTjsNotEncrypted && VFS.IsPathEqualsToFileName(name, "startup.tjs"))
                    };
                    bool compress = compress_contents && ShouldCompressFile(entry);
                    using (var file = File.Open(name, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        if (!xp3entry.IsEncrypted || 0 == file.Length)
                            RawFileCopy(file, xp3entry, output, compress);
                        else
                            EncryptedFileCopy(file, xp3entry, output, compress);
                    }

                    dir.Add(xp3entry);
                }

                long index_pos = writer.BaseStream.Position;
                writer.BaseStream.Position = index_pos_offset;
                writer.Write(index_pos);
                writer.BaseStream.Position = index_pos;

                using (var header = new BinaryWriter(new MemoryStream(dir.Count * 0x58), Encoding.Unicode))
                {
                    if (null != callback)
                        callback(callback_count++, null, arcStrings.MsgWritingIndex);

                    long dir_pos = 0;
                    if (3 == xp3_options.Version)
                    {
                        foreach (var entry in dir)
                        {
                            header.Write((uint)0x6e666e68); // "hnfn"
                            header.Write((long)(4 + 2 + entry.Name.Length * 2));
                            header.Write((uint)entry.Hash);
                            header.Write((short)entry.Name.Length);
                            foreach (char c in entry.Name)
                                header.Write(c);
                        }
                        dir_pos = header.BaseStream.Position;
                    }
                    foreach (var entry in dir)
                    {
                        var entry_name = entry.Name;
                        if (3 == xp3_options.Version)
                        {
                            using (var md5 = MD5.Create())
                            {
                                var text_bytes = Encoding.Unicode.GetBytes(entry.Name.ToLowerInvariant());
                                var hash = md5.ComputeHash(text_bytes);
                                var sb = new StringBuilder(32);
                                for (int i = 0; i < hash.Length; ++i)
                                    sb.AppendFormat("{0:x2}", hash[i]);
                                entry_name = sb.ToString();
                            }
                        }
                        header.BaseStream.Position = dir_pos;
                        header.Write((uint)0x656c6946); // "File"
                        long header_size_pos = header.BaseStream.Position;
                        header.Write((long)0);
                        header.Write((uint)0x6f666e69); // "info"
                        header.Write((long)(4 + 8 + 8 + 2 + entry_name.Length * 2));
                        header.Write((uint)(use_encryption ? 0x80000000 : 0));
                        header.Write((long)entry.UnpackedSize);
                        header.Write((long)entry.Size);

                        header.Write((short)entry_name.Length);
                        foreach (char c in entry_name)
                            header.Write(c);

                        header.Write((uint)0x6d676573); // "segm"
                        header.Write((long)0x1c);
                        var segment = entry.Segments.First();
                        header.Write((int)(segment.IsCompressed ? 1 : 0));
                        header.Write((long)segment.Offset);
                        header.Write((long)segment.Size);
                        header.Write((long)segment.PackedSize);

                        header.Write((uint)0x726c6461); // "adlr"
                        header.Write((long)4);
                        header.Write((uint)entry.Hash);

                        dir_pos = header.BaseStream.Position;
                        long header_size = dir_pos - header_size_pos - 8;
                        header.BaseStream.Position = header_size_pos;
                        header.Write(header_size);
                    }

                    header.BaseStream.Position = 0;
                    writer.Write(compress_index);
                    long unpacked_dir_size = header.BaseStream.Length;
                    if (compress_index)
                    {
                        if (null != callback)
                            callback(callback_count++, null, arcStrings.MsgCompressingIndex);

                        long packed_dir_size_pos = writer.BaseStream.Position;
                        writer.Write((long)0);
                        writer.Write(unpacked_dir_size);

                        long dir_start = writer.BaseStream.Position;
                        using (var zstream = new ZLibStream(writer.BaseStream, CompressionMode.Compress,
                                                             CompressionLevel.Level9, true))
                            header.BaseStream.CopyTo(zstream);

                        long packed_dir_size = writer.BaseStream.Position - dir_start;
                        writer.BaseStream.Position = packed_dir_size_pos;
                        writer.Write(packed_dir_size);
                    }
                    else
                    {
                        writer.Write(unpacked_dir_size);
                        header.BaseStream.CopyTo(writer.BaseStream);
                    }
                }
            }
            output.Seek(0, SeekOrigin.End);
        }

        void RawFileCopy(FileStream file, Xp3Entry xp3entry, Stream output, bool compress)
        {
            if (file.Length > uint.MaxValue)
                throw new FileSizeException();

            uint unpacked_size = (uint)file.Length;
            xp3entry.UnpackedSize = (uint)unpacked_size;
            xp3entry.Size = (uint)unpacked_size;
            compress = compress && unpacked_size > 0;
            var segment = new Xp3Segment
            {
                IsCompressed = compress,
                Offset = output.Position,
                Size = unpacked_size,
                PackedSize = unpacked_size
            };
            if (compress)
            {
                var start = output.Position;
                using (var zstream = new ZLibStream(output, CompressionMode.Compress, CompressionLevel.Level9, true))
                {
                    xp3entry.Hash = CheckedCopy(file, zstream);
                }
                segment.PackedSize = (uint)(output.Position - start);
                xp3entry.Size = segment.PackedSize;
            }
            else
            {
                xp3entry.Hash = CheckedCopy(file, output);
            }
            xp3entry.Segments.Add(segment);
        }

        void EncryptedFileCopy(FileStream file, Xp3Entry xp3entry, Stream output, bool compress)
        {
            if (file.Length > int.MaxValue)
                throw new FileSizeException();

            using (var map = MemoryMappedFile.CreateFromFile(file, null, 0,
                    MemoryMappedFileAccess.Read, null, HandleInheritability.None, true))
            {
                uint unpacked_size = (uint)file.Length;
                xp3entry.UnpackedSize = (uint)unpacked_size;
                xp3entry.Size = (uint)unpacked_size;
                using (var view = map.CreateViewAccessor(0, unpacked_size, MemoryMappedFileAccess.Read))
                {
                    var segment = new Xp3Segment
                    {
                        IsCompressed = compress,
                        Offset = output.Position,
                        Size = unpacked_size,
                        PackedSize = unpacked_size,
                    };
                    if (compress)
                    {
                        output = new ZLibStream(output, CompressionMode.Compress, CompressionLevel.Level9, true);
                    }
                    unsafe
                    {
                        byte[] read_buffer = new byte[81920];
                        byte* ptr = view.GetPointer(0);
                        try
                        {
                            var checksum = new Adler32();
                            bool hash_after_crypt = xp3entry.Cipher.HashAfterCrypt;
                            if (!hash_after_crypt)
                                xp3entry.Hash = checksum.Update(ptr, (int)unpacked_size);
                            int offset = 0;
                            int remaining = (int)unpacked_size;
                            while (remaining > 0)
                            {
                                int amount = Math.Min(remaining, read_buffer.Length);
                                remaining -= amount;
                                Marshal.Copy((IntPtr)(ptr + offset), read_buffer, 0, amount);
                                xp3entry.Cipher.Encrypt(xp3entry, offset, read_buffer, 0, amount);
                                if (hash_after_crypt)
                                    checksum.Update(read_buffer, 0, amount);
                                output.Write(read_buffer, 0, amount);
                                offset += amount;
                            }
                            if (hash_after_crypt)
                                xp3entry.Hash = checksum.Value;
                        }
                        finally
                        {
                            view.SafeMemoryMappedViewHandle.ReleasePointer();
                            if (compress)
                            {
                                var dest = (output as ZLibStream).BaseStream;
                                output.Dispose();
                                segment.PackedSize = (uint)(dest.Position - segment.Offset);
                                xp3entry.Size = segment.PackedSize;
                            }
                            xp3entry.Segments.Add(segment);
                        }
                    }
                }
            }
        }

        uint CheckedCopy(Stream src, Stream dst)
        {
            var checksum = new Adler32();
            var read_buffer = new byte[81920];
            for (; ; )
            {
                int read = src.Read(read_buffer, 0, read_buffer.Length);
                if (0 == read)
                    break;
                checksum.Update(read_buffer, 0, read);
                dst.Write(read_buffer, 0, read);
            }
            return checksum.Value;
        }

        bool ShouldCompressFile(Entry entry)
        {
            if ("image" == entry.Type || "archive" == entry.Type)
                return false;
            if (entry.Name.HasExtension(".ogg"))
                return false;
            return true;
        }

        ICrypt GuessCryptAlgorithm(ArcView file)
        {
            var title = FormatCatalog.Instance.LookupGame(file.Name);
            if (string.IsNullOrEmpty(title))
                title = FormatCatalog.Instance.LookupGame(file.Name, @"..\*.exe");
            if (string.IsNullOrEmpty(title))
                return null;
            ICrypt algorithm;
            if (!KnownSchemes.TryGetValue(title, out algorithm))
            {
                if (NoCryptTitles.Contains(title))
                    algorithm = NoCryptAlgorithm;
                else
                    algorithm = null; //ダイアログ表示
            }
            m_title = title;
            return algorithm;
        }

        static Xp3Scheme KiriKiriScheme = new Xp3Scheme
        {
            KnownSchemes = new Dictionary<string, ICrypt>(),
            NoCryptTitles = new HashSet<string>()
        };

        public static IDictionary<string, ICrypt> KnownSchemes
        {
            get { return KiriKiriScheme.KnownSchemes; }
        }

        public static ISet<string> NoCryptTitles
        {
            get { return KiriKiriScheme.NoCryptTitles; }
        }

        public override ResourceScheme Scheme
        {
            get { return KiriKiriScheme; }
            set { KiriKiriScheme = (Xp3Scheme)value; }
        }
    }

    internal class Xp3Stream : Stream
    {
        ArcView m_file;
        Xp3Entry m_entry;
        IEnumerator<Xp3Segment> m_segment;
        Stream m_stream;
        long m_offset = 0;
        bool m_eof = false;

        public override bool CanRead { get { return !disposed; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return m_entry.UnpackedSize; } }
        public override long Position
        {
            get { return m_offset; }
            set { throw new NotSupportedException("Xp3Stream.Position not supported."); }
        }

        public Xp3Stream(ArcView file, Xp3Entry entry)
        {
            m_file = file;
            m_entry = entry;
            m_segment = entry.Segments.GetEnumerator();
            NextSegment();
        }

        private void NextSegment()
        {
            if (!m_segment.MoveNext())
            {
                m_eof = true;
                return;
            }
            if (null != m_stream)
                m_stream.Dispose();
            var segment = m_segment.Current;
            var segment_size = segment.IsCompressed ? segment.PackedSize : segment.Size;
            m_stream = m_file.CreateStream(segment.Offset, segment_size);
            if (segment.IsCompressed)
                m_stream = new ZLibStream(m_stream, CompressionMode.Decompress);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (!m_eof && count > 0)
            {
                int read = m_stream.Read(buffer, offset, count);
                if (0 != read)
                {
                    if (m_entry.IsEncrypted)
                        m_entry.Cipher.Decrypt(m_entry, m_offset, buffer, offset, read);                    
                    m_offset += read;
                    total += read;
                    offset += read;
                    count -= read;
                }
                if (0 != count)
                    NextSegment();
            }
            return total;
        }

        public override int ReadByte()
        {
            int b = -1;
            while (!m_eof)
            {
                b = m_stream.ReadByte();
                if (-1 != b)
                {
                    if (m_entry.IsEncrypted)
                        b = m_entry.Cipher.Decrypt(m_entry, m_offset++, (byte)b);
                    break;
                }
                NextSegment();
            }
            return b;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException("Xp3Stream.Seek method is not supported");
        }

        public override void SetLength(long length)
        {
            throw new NotSupportedException("Xp3Stream.SetLength method is not supported");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Xp3Stream.Write method is not supported");
        }

        public override void WriteByte(byte value)
        {
            throw new NotSupportedException("Xp3Stream.WriteByte method is not supported");
        }

        #region IDisposable Members
        bool disposed = false;
        protected override void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (null != m_stream)
                        m_stream.Dispose();
                    m_segment.Dispose();
                }
                disposed = true;
                base.Dispose(disposing);
            }
        }
        #endregion
    }

    /// <summary>
    /// Class that maps file hashes to filenames.
    /// </summary>
    internal sealed class FilenameMap : IDisposable
    {
        Dictionary<uint, string> m_hash_map = new Dictionary<uint, string>();
        Dictionary<string, string> m_md5_map = new Dictionary<string, string>();
        MD5 m_md5 = MD5.Create();
        StringBuilder m_md5_str = new StringBuilder();

        public int Count { get { return m_md5_map.Count; } }

        public void Add(uint hash, string filename)
        {
            if (!m_hash_map.ContainsKey(hash))
                m_hash_map[hash] = filename;

            m_md5_map[GetMd5Hash(filename)] = filename;
        }

        public void AddShortcut(string shortcut, string filename)
        {
            m_md5_map[shortcut] = filename;
        }

        public string Get(uint hash, string md5)
        {
            string filename;
            if (m_md5_map.TryGetValue(md5, out filename))
                return filename;
            if (m_hash_map.TryGetValue(hash, out filename))
                return filename;
            return md5;
        }

        string GetMd5Hash(string text)
        {
            var text_bytes = Encoding.Unicode.GetBytes(text.ToLowerInvariant());
            var md5 = m_md5.ComputeHash(text_bytes);
            m_md5_str.Clear();
            for (int i = 0; i < md5.Length; ++i)
                m_md5_str.AppendFormat("{0:x2}", md5[i]);
            return m_md5_str.ToString();
        }

        bool _disposed = false;
        public void Dispose()
        {
            if (!_disposed)
            {
                m_md5.Dispose();
                _disposed = true;
            }
        }
    }

    [Export(typeof(ResourceAlias))]
    [ExportMetadata("Extension", "ANM")]
    [ExportMetadata("Target", "TXT")]
    public class AnmFormat : ResourceAlias { }

    [Export(typeof(ResourceAlias))]
    [ExportMetadata("Extension", "ASD")]
    [ExportMetadata("Target", "TXT")]
    public class AsdFormat : ResourceAlias { }
}
