//-----------------------------------------------------------------------------
//  This is an example application for analyzing the symbols from an executable
//  extracted either from the PDB or from a dump using DumpBin /headers.  More
//  documentation is available at http://gameangst.com/?p=320
//
//  This code was authored and released into the public domain by
//  Adrian Stone (stone@gameangst.com).
//
//  THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
//  SHALL ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER 
//  LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//-----------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Globalization;

using Dia2Lib;
using System.Runtime.InteropServices;

using System.Collections;
using System.Reflection;

// Most of the interop with msdia90.dll can be generated automatically
// by added the DLL as a reference in the C# application.  Below are
// definitions for elements that can't be generated automatically.
namespace Dia2Lib
{
    [Guid("0CF4B60E-35B1-4c6c-BDD8-854B9C8E3857")]
    [InterfaceType(1)]
    public interface IDiaSectionContrib
    {
        IDiaSymbol compiland { get; }
        uint addressSection { get; }
        uint addressOffset { get; }
        uint relativeVirtualAddress { get; }
        ulong virtualAddress { get; }
        uint length { get; }
        bool notPaged { get; }
        bool code { get; }
        bool initializedData { get; }
        bool uninitializedData { get; }
        bool remove { get; }
        bool comdat { get; }
        bool discardable { get; }
        bool notCached { get; }
        bool share { get; }
        bool execute { get; }
        bool read { get; }
        bool write { get; }
        uint dataCrc { get; }
        uint relocationsCrc { get; }
        uint compilandId { get; }
        bool code16bit { get; }
    }

    [Guid("1994DEB2-2C82-4b1d-A57F-AFF424D54A68")]
    [InterfaceType(1)]
    public interface IDiaEnumSectionContribs
    {
        [DispId(1)]
        int count { get; }

        void Clone(out IDiaEnumSectionContribs ppenum);
        IDiaSectionContrib Item(uint index);
        void Next(uint celt, out IDiaSectionContrib rgelt, out uint pceltFetched);
        void Reset();
        void Skip(uint celt);
    }

    enum NameSearchOptions
    {
        nsNone = 0,
        nsfCaseSensitive = 0x1,
        nsfCaseInsensitive = 0x2,
        nsfFNameExt = 0x4,
        nsfRegularExpression = 0x8,
        nsfUndecoratedName = 0x10,
        nsCaseSensitive = nsfCaseSensitive,
        nsCaseInsensitive = nsfCaseInsensitive,
        nsFNameExt = (nsfCaseInsensitive | nsfFNameExt),
        nsRegularExpression = (nsfRegularExpression | nsfCaseSensitive),
        nsCaseInRegularExpression = (nsfRegularExpression | nsfCaseInsensitive)
    } ;

    enum DataKind
    {
        DataIsUnknown,
        DataIsLocal,
        DataIsStaticLocal,
        DataIsParam,
        DataIsObjectPtr,
        DataIsFileStatic,
        DataIsGlobal,
        DataIsMember,
        DataIsStaticMember,
        DataIsConstant
    }
}

namespace SymbolSort
{
    class Symbol
    {
        public int          size;
        public int          count;
        public int          rva;
        public string       name;
        public string       short_name;
        public string       source_filename;
        public string       section;
    };

    class MergedSymbol
    {
        public string   id;
        public int      total_count;
        public int      total_size;
    };

    enum InputType
    {
        pdb,
        comdat,
        nm_sysv,
        nm_bsd
    };

    class InputFile
    {
        public string       filename;
        public InputType    type;
        public InputFile(string filename, InputType type)
        {
            this.filename = filename;
            this.type = type;
        }
    }

    class SymbolSort
    {
        private static string PathCanonicalize(string path)
        {
            if (path.Length == 0)
                return path;

            string[] dirs = path.Split("/\\".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            List<string> outDirs = new List<string>();
            int skipCount = 0;
            for (int i=dirs.Length-1; i>=0; --i)
            {
                string dir = dirs[i];
                if (dir == ".")
                {
                }
                else if (dir == "..")
                    ++skipCount;
                else if (skipCount > 0)
                    --skipCount;
                else
                    outDirs.Add(dir);
            }

            string outPath = "";
            if (path[0] == '\\' || path[0] == '/')
            {
                outPath = "\\";
            }

            for (int i = 0; i < skipCount; ++i)
            {
                outPath += "..\\";
            }

            for (int i=outDirs.Count-1; i>=0; --i)
            {
                outPath += outDirs[i];
                outPath += "\\";
            }

            if (outPath.Length > 1 && path[path.Length-1] != '\\' && path[path.Length-1] != '/')
            {
                outPath = outPath.Remove(outPath.Length - 1);
            }

            return outPath;
        }

        private static string ExtractGroupedSubstrings(string name, char groupBegin, char groupEnd, string groupReplace)
        {
            string ungrouped_name = "";
            int groupDepth = 0;
            int istart = 0;
            for (int i = 0; i < name.Length; ++i)
            {
                char c = name[i];
                if (c == groupEnd && groupDepth > 0)
                {
                    if (--groupDepth == 0)
                    {
                        ungrouped_name += groupReplace;
                        ungrouped_name += groupEnd;
                        istart = i + 1;
                    }
                }
                else if (c == groupBegin)
                {
                    if (groupDepth++ == 0)
                    {
                        ungrouped_name += name.Substring(istart, i - istart + 1);
                    }
                }
            }

            if (groupDepth == 0 && istart < name.Length)
            {
                ungrouped_name += name.Substring(istart, name.Length - istart);
            }

            return ungrouped_name;
        }

        private static void ParseBsdSymbol(string line, out Symbol symbol)
        {
            symbol = null;

            int rva = 0;
            int size = 0;
            string name;
            string section = "";
            string sourceFilename = "";

            string[] tokens = line.Split((char[])null, 2, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2)
                return;

            if (tokens[0].Length > 1)
            {
                rva = Int32.Parse(tokens[0], NumberStyles.AllowHexSpecifier);
                tokens = tokens[1].Split((char[])null, 2, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2)
                    return;
            }

            if (tokens[0].Length > 1)
            {
                try
                {
                    size = Int32.Parse(tokens[0], NumberStyles.AllowHexSpecifier);
                }
                catch (System.Exception)
                {
                }
                tokens = tokens[1].Split((char[])null, 2, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2)
                    return;
            }

            section = tokens[0];
            tokens = tokens[1].Split("\t\r\n".ToCharArray(), 2, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 1)
                return;

            name = tokens[0];
            if (tokens.Length > 1)
            {
                sourceFilename = tokens[1];
            }

            symbol = new Symbol();
            symbol.name = name;
            symbol.short_name = name;
            symbol.rva = rva;
            symbol.size = size;
            symbol.count = 1;
            symbol.section = section;
            symbol.source_filename = sourceFilename;
        }

        private static void ParseSysvSymbol(string line, out Symbol symbol)
        {
            symbol = null;

            string[] tokens = line.Split("|".ToCharArray(), 7);

            if (tokens.Length < 7)
                return;

            int rva = 0;
            int size = 0;
            string name;
            string section = "";
            string sourceFilename = "";

            name = tokens[0].Trim();

            if (tokens[1].Trim().Length > 0)
            {
                rva = Int32.Parse(tokens[1], NumberStyles.AllowHexSpecifier);
            }
            if (tokens[4].Trim().Length > 0)
            {
                try
                {
                    size = Int32.Parse(tokens[4], NumberStyles.AllowHexSpecifier);
                }
                catch (System.Exception)
                {
                }
            }
            tokens = tokens[6].Split("\t\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length > 0)
            {
                section = tokens[0].Trim();
            }
            if (tokens.Length > 1)
            {
                sourceFilename = tokens[1].Trim();
            }

            symbol = new Symbol();
            symbol.name = name;
            symbol.short_name = name;
            symbol.rva = rva;
            symbol.size = size;
            symbol.count = 1;
            symbol.section = section;
            symbol.source_filename = sourceFilename;
        }

        private static void ReadSymbolsFromNM(List<Symbol> symbols, string inFilename, InputType inType)
        {
            StreamReader reader = new StreamReader(inFilename);

            Console.Write("Reading symbols...");
            int percentComplete = 0;
            Console.Write(" {0,3}% complete\b\b\b\b\b\b\b\b\b\b\b\b\b", percentComplete);

            while (!reader.EndOfStream)
            {
                int newPercentComplete = (int)(100 * reader.BaseStream.Position / reader.BaseStream.Length);
                if (newPercentComplete != percentComplete)
                {
                    percentComplete = newPercentComplete;
                    Console.Write("{0,3}\b\b\b", percentComplete);
                }

                string ln;
                do
                {
                    ln = reader.ReadLine();
                }
                while (!reader.EndOfStream && ln == "");

                Symbol symbol = null;
                if (inType == InputType.nm_bsd)
                {
                    ParseBsdSymbol(ln, out symbol);
                }
                else if (inType == InputType.nm_sysv)
                {
                    ParseSysvSymbol(ln, out symbol);
                }

                if (symbol != null)
                {
                    symbols.Add(symbol);
                }
            }

            Console.WriteLine("{0,3}", 100);

            Console.WriteLine("Cleaning up paths...");
            HashSet<string> rootPaths = new HashSet<string>();
            foreach (Symbol s in symbols)
            {
                if (s.source_filename.Length > 0)
                {
                    int lineNumberLoc = s.source_filename.LastIndexOf(':');
                    if (lineNumberLoc > 0)
                    {
                        s.source_filename = s.source_filename.Substring(0, lineNumberLoc);
                    }
                    if (Path.IsPathRooted(s.source_filename))
                    {
                        string canonicalPath = PathCanonicalize(s.source_filename);
                        canonicalPath = canonicalPath.ToLower();
                        s.source_filename = canonicalPath;
                        rootPaths.Add(Path.GetDirectoryName(canonicalPath));
                    }
                }
            }

            foreach (Symbol s in symbols)
            {
                if (s.source_filename.Length > 0)
                {
                    if (!Path.IsPathRooted(s.source_filename))
                    {
                        bool found = false;
                        foreach (String path in rootPaths)
                        {
                            string fullPath = Path.Combine(path, s.source_filename);
                            fullPath = PathCanonicalize(fullPath);
                            fullPath = fullPath.ToLower();

                            if (rootPaths.Contains(Path.GetDirectoryName(fullPath)))
                            {
                                s.source_filename = fullPath;
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            s.source_filename = PathCanonicalize(s.source_filename).ToLower();
                        }
                    }
                }
            }
        }

        private static void ReadSymbolsFromCOMDAT(List<Symbol> symbols, string inFilename)
        {
            Regex regexName = new Regex(@"\n[ \t]*([^ \t]+)[ \t]+name");
            Regex regexSize = new Regex(@"\n[ \t]*([A-Za-z0-9]+)[ \t]+size of raw data");
            Regex regexCOMDAT = new Regex(@"\n[ \t]*COMDAT; sym= \""([^\n\""]+)");

            StreamReader reader = new StreamReader(inFilename);

            string curSourceFilename = "";

            Console.Write("Reading symbols...");
            int percentComplete = 0;
            Console.Write(" {0,3}% complete\b\b\b\b\b\b\b\b\b\b\b\b\b", percentComplete);

            while (!reader.EndOfStream)
            {
                int newPercentComplete = (int)(100 * reader.BaseStream.Position / reader.BaseStream.Length);
                if (newPercentComplete != percentComplete)
                {
                    percentComplete = newPercentComplete;
                    Console.Write("{0,3}\b\b\b", percentComplete);
                }

                string ln;
                do
                {
                    ln = reader.ReadLine();
                }
                while (!reader.EndOfStream && ln == "");

                if (ln.StartsWith("SECTION HEADER"))
                {
                    string record = "";
                    while (!reader.EndOfStream)
                    {
                        ln = reader.ReadLine();
                        if (ln == "")
                            break;

                        record += "\n";
                        record += ln;
                    }

                    Symbol symbol = new Symbol();

                    try
                    {
                        Match m;

                        m = regexCOMDAT.Match(record);
                        symbol.name = m.Groups[1].Value;
                        if (symbol.name != "")
                        {
                            symbol.rva = 0;
                            symbol.source_filename = curSourceFilename;
                            symbol.short_name = symbol.name;
                            m = regexName.Match(record);
                            symbol.section = m.Groups[1].Value;

                            m = regexSize.Match(record);
                            symbol.size = Int32.Parse(m.Groups[1].Value, NumberStyles.AllowHexSpecifier);
                            symbol.count = 1;

                            symbols.Add(symbol);
                        }
                    }
                    catch (System.Exception)
                    {
                    }
                }
                else if (ln.StartsWith("Dump of file "))
                {
                    curSourceFilename = ln.Substring("Dump of file ".Length);
                }
                else
                {
                    while (!reader.EndOfStream && ln != "")
                    {
                        ln = reader.ReadLine();
                    }
                }
            }

            Console.WriteLine("{0,3}", 100);
        }

        private static string FindSourceFileForRVA(IDiaSession session, uint rva, uint rvaLength)
        {
            IDiaEnumLineNumbers enumLineNumbers;
            session.findLinesByRVA(rva, rvaLength, out enumLineNumbers);
            if (enumLineNumbers != null)
            {
                for ( ; ; )
                {
                    uint numFetched = 1;
                    IDiaLineNumber lineNumber;
                    enumLineNumbers.Next(numFetched, out lineNumber, out numFetched);
                    if (lineNumber == null || numFetched < 1)
                        break;

                    IDiaSourceFile sourceFile = lineNumber.sourceFile;
                    if (sourceFile != null)
                    {
                        return sourceFile.fileName.ToLower();
                    }
                }
            }
            return "";
        }


        private static IDiaEnumSectionContribs GetEnumSectionContribs(IDiaSession session)
        {
            IDiaEnumTables tableEnum;
            session.getEnumTables(out tableEnum);

            for ( ; ; )
            {
                uint numFetched = 1;
                IDiaTable table = null;
                tableEnum.Next(numFetched, ref table, ref numFetched);
                if (table == null || numFetched < 1)
                    break;

                try
                {
                    IDiaEnumSectionContribs enumSectionContribs = (IDiaEnumSectionContribs)table;
                    if (enumSectionContribs != null)
                        return enumSectionContribs;
                }
                catch (Exception)
                {
                }
            }

            return null;
        }

        private enum SourceFileType
        {
            cpp,
            unknown,
            h
        };
        private static SourceFileType GetSourceFileType(string filename)
        {
            string ext = Path.GetExtension(filename).ToLower();
            if (String.Compare(ext, 0, ".c", 0, 2) == 0)
                return SourceFileType.cpp;
            if (String.Compare(ext, 0, ".h", 0, 2) == 0 ||
                ext == ".pch")
                return SourceFileType.h;
            return SourceFileType.unknown;

        }
        private static string FindBestSourceFileForCompiland(IDiaSession session, IDiaSymbol compiland, Dictionary<string, int> sourceFileUsage)
        {
            string bestSourceFileName = "";
            IDiaEnumSourceFiles enumSourceFiles;
            session.findFile(compiland, null, 0, out enumSourceFiles);
            if (enumSourceFiles != null)
            {
                int bestSourceFileCount = int.MaxValue;
                SourceFileType bestSourceFileType = SourceFileType.h;


                for ( ; ; )
                {
                    IDiaSourceFile sourceFile;
                    uint numFetched = 1;
                    enumSourceFiles.Next(numFetched, out sourceFile, out numFetched);
                    if (sourceFile == null || numFetched < 1)
                        break;
                    int usage = sourceFileUsage[sourceFile.fileName];
                    if (usage < bestSourceFileCount)
                    {
                        bestSourceFileName = sourceFile.fileName;
                        bestSourceFileType = GetSourceFileType(sourceFile.fileName);
                        bestSourceFileCount = usage;
                    }
                    else if (usage == bestSourceFileCount && bestSourceFileType != SourceFileType.cpp)
                    {
                        SourceFileType type = GetSourceFileType(sourceFile.fileName);
                        if (type < bestSourceFileType)
                        {
                            bestSourceFileName = sourceFile.fileName;
                            bestSourceFileType = type;
                        }
                    }
                }
            }
            return bestSourceFileName.ToLower();
        }

        private static IDiaSectionContrib FindSectionContribForRVA(int rva, List<IDiaSectionContrib> sectionContribs)
        {
            int i0 = 0, i1 = sectionContribs.Count;
            while (i0 < i1)
            {
                int i = (i1 + i0) / 2;
                if (sectionContribs[i].relativeVirtualAddress > rva)
                {
                    i1 = i;
                }
                else if (sectionContribs[i].relativeVirtualAddress + sectionContribs[i].length <= rva)
                {
                    i0 = i+1;
                }
                else
                {
                    return sectionContribs[i];
                }
            }
            return null;
       }

        private static void BuildCompilandFileMap(IDiaSession session, Dictionary<uint, string> compilandFileMap)
        {
            IDiaSymbol globalScope = session.globalScope;

            Dictionary<string, int> sourceFileUsage = new Dictionary<string, int>();
            {
                IDiaEnumSymbols enumSymbols;
                globalScope.findChildren(Dia2Lib.SymTagEnum.SymTagCompiland, null, 0, out enumSymbols);

                for (; ; )
                {
                    uint numFetched = 1;
                    IDiaSymbol compiland;
                    enumSymbols.Next(numFetched, out compiland, out numFetched);
                    if (compiland == null || numFetched < 1)
                        break;

                    IDiaEnumSourceFiles enumSourceFiles;
                    session.findFile(compiland, null, 0, out enumSourceFiles);
                    if (enumSourceFiles != null)
                    {
                        for (; ; )
                        {
                            IDiaSourceFile sourceFile;
                            uint numFetched2 = 1;
                            enumSourceFiles.Next(numFetched2, out sourceFile, out numFetched2);
                            if (sourceFile == null || numFetched2 < 1)
                                break;
                            if (sourceFileUsage.ContainsKey(sourceFile.fileName))
                            {
                                sourceFileUsage[sourceFile.fileName]++;
                            }
                            else
                            {
                                sourceFileUsage.Add(sourceFile.fileName, 1);
                            }
                        }
                    }
                }
            }

            {
                IDiaEnumSymbols enumSymbols;
                globalScope.findChildren(Dia2Lib.SymTagEnum.SymTagCompiland, null, 0, out enumSymbols);

                for (; ; )
                {
                    uint numFetched = 1;
                    IDiaSymbol compiland;
                    enumSymbols.Next(numFetched, out compiland, out numFetched);
                    if (compiland == null || numFetched < 1)
                        break;

                    compilandFileMap.Add(compiland.symIndexId, FindBestSourceFileForCompiland(session, compiland, sourceFileUsage));
                }
            }
        }

        private static void BuildSectionContribTable(IDiaSession session, List<IDiaSectionContrib> sectionContribs)
        {
            {
                IDiaEnumSectionContribs enumSectionContribs = GetEnumSectionContribs(session);
                if (enumSectionContribs != null)
                {
                    for (; ; )
                    {
                        uint numFetched = 1;
                        IDiaSectionContrib diaSectionContrib;
                        enumSectionContribs.Next(numFetched, out diaSectionContrib, out numFetched);
                        if (diaSectionContrib == null || numFetched < 1)
                            break;

                        sectionContribs.Add(diaSectionContrib);

                    }
                }
            }
            sectionContribs.Sort(
                delegate(IDiaSectionContrib s0, IDiaSectionContrib s1)
                {
                    return (int)s0.relativeVirtualAddress - (int)s1.relativeVirtualAddress;
                } );
        }


        private static void ReadSymbolsFromPDB(List<Symbol> symbols, string filename, string searchPath)
        {
            DiaSourceClass diaSource = new DiaSourceClass();

            if (Path.GetExtension(filename).ToLower() == ".pdb")
            {
                diaSource.loadDataFromPdb(filename);
            }
            else
            {
                diaSource.loadDataForExe(filename, searchPath, null);
            }

            IDiaSession diaSession;
            diaSource.openSession(out diaSession);

            Console.WriteLine("Reading section info...");
            List<IDiaSectionContrib> sectionContribs = new List<IDiaSectionContrib>();
            BuildSectionContribTable(diaSession, sectionContribs);

            Console.WriteLine("Reading source file info...");
            Dictionary<uint, string> compilandFileMap = new Dictionary<uint, string>();
            BuildCompilandFileMap(diaSession, compilandFileMap);

            IDiaSymbol globalScope = diaSession.globalScope;

            {
                IDiaEnumSymbols enumSymbols;
                globalScope.findChildren(Dia2Lib.SymTagEnum.SymTagData, null, 0, out enumSymbols);

                uint numSymbols = (uint)enumSymbols.count;
                uint symbolsRead = 0;
                uint percentComplete = 0;

                Console.Write("Reading data symbols...");
                Console.Write(" {0,3}% complete\b\b\b\b\b\b\b\b\b\b\b\b\b", percentComplete);
                for ( ; ; )
                {
                    uint numFetched = 1;
                    IDiaSymbol diaSymbol;
                    enumSymbols.Next(numFetched, out diaSymbol, out numFetched);
                    if (diaSymbol == null || numFetched < 1)
                        break;

                    uint newPercentComplete = 100 * ++symbolsRead / numSymbols;
                    if (percentComplete < newPercentComplete)
                    {
                        percentComplete = newPercentComplete;
                        Console.Write("{0,3}\b\b\b", percentComplete);
                    }

                    if (diaSymbol.type == null)
                        continue;

                    switch ((DataKind)diaSymbol.dataKind)
                    {
                        case DataKind.DataIsLocal:
                        case DataKind.DataIsParam:
                        case DataKind.DataIsObjectPtr:
                        case DataKind.DataIsMember:
                            continue;
                    }

                    Symbol symbol = new Symbol();
                    symbol.size = (int)diaSymbol.type.length;
                    symbol.count = 1;
                    symbol.rva = (int)diaSymbol.relativeVirtualAddress;
                    symbol.short_name = diaSymbol.name == null ? "" : diaSymbol.name;
                    symbol.name = diaSymbol.undecoratedName == null ? symbol.short_name : diaSymbol.undecoratedName;
                    IDiaSectionContrib sectionContrib = FindSectionContribForRVA(symbol.rva, sectionContribs);
                    symbol.source_filename = sectionContrib == null ? "" : compilandFileMap[sectionContrib.compilandId];
                    symbol.section = sectionContrib == null ? "data" : (sectionContrib.uninitializedData ? "bss" : (sectionContrib.write ? "data" : "rdata"));

                    symbols.Add(symbol);
                }
                Console.WriteLine("{0,3}%", 100);
            }

            {
                IDiaEnumSymbols enumSymbols;
                globalScope.findChildren(Dia2Lib.SymTagEnum.SymTagFunction, null, 0, out enumSymbols);

                uint numSymbols = (uint)enumSymbols.count;
                uint symbolsRead = 0;
                uint percentComplete = 0;

                Console.Write("Reading function symbols...");
                Console.Write(" {0,3}% complete\b\b\b\b\b\b\b\b\b\b\b\b\b", percentComplete);
                for (; ; )
                {
                    uint numFetched = 1;
                    IDiaSymbol diaSymbol;
                    enumSymbols.Next(numFetched, out diaSymbol, out numFetched);
                    if (diaSymbol == null || numFetched < 1)
                        break;

                    uint newPercentComplete = 100 * ++symbolsRead / numSymbols;
                    if (percentComplete < newPercentComplete)
                    {
                        percentComplete = newPercentComplete;
                        Console.Write("{0,3}\b\b\b", percentComplete);
                    }

                    if (diaSymbol.length == 0)
                        continue;

                    Symbol symbol = new Symbol();
                    symbol.short_name = diaSymbol.name == null ? "" : diaSymbol.name;
                    symbol.name = diaSymbol.undecoratedName == null ? symbol.short_name : diaSymbol.undecoratedName;
                    symbol.rva = (int)diaSymbol.relativeVirtualAddress;
                    symbol.source_filename = FindSourceFileForRVA(diaSession, diaSymbol.relativeVirtualAddress, (uint)diaSymbol.length);
                    symbol.section = "code";
                    symbol.size = (int)diaSymbol.length;
                    symbol.count = 1;

                    symbols.Add(symbol);
                }
                Console.WriteLine("{0,3}%", 100);
            }

            Console.WriteLine("Subtracting overlapping symbols...");
            {
                symbols.Sort(
                    delegate(Symbol s0, Symbol s1)
                    {
                        if (s0.rva == s1.rva)
                        {
                            return s1.name.Length - s0.name.Length;
                        }
                        return s0.rva - s1.rva;
                    } );

                int highWaterMark = 0;
                for (int i = 0, count = symbols.Count; i < count; ++i)
                {
                    Symbol s = symbols[i];
                    int symbolStart = s.rva;
                    int symbolEnd = s.rva + s.size;
                    int overlapStart = symbolStart;
                    int overlapEnd = Math.Max(overlapStart, Math.Min(symbolEnd, highWaterMark));
                    s.size -= overlapEnd - symbolStart;
                    highWaterMark = Math.Max(highWaterMark, symbolEnd);
                }
            }

        }

        private static void WriteSymbolList(TextWriter writer, List<Symbol> symbolList, int maxCount)
        {
            writer.WriteLine("{0,12} {1,12}  {2,-120}  {3}",
                "Size", "Section/Type", "Name", "Source");

            int count = maxCount;
            foreach (Symbol s in symbolList)
            {
                if (count-- == 0)
                    break;
                writer.WriteLine("{0,12} {1,12}  {2,-120}  {3}",
                    s.size,
                    s.section,
                    s.name,
                    s.source_filename);
            }
            writer.WriteLine();
        }

        private static void WriteMergedSymbolList(TextWriter writer, IEnumerable<MergedSymbol> symbolList, int maxCount, Func<MergedSymbol, bool> predicate)
        {
            writer.WriteLine("{0,12} {1,12}  {2}",
                 "Total Size", "Total Count", "Name");

            int count = maxCount;
            foreach (MergedSymbol s in symbolList)
            {
                if (!predicate(s))
                    continue;
                if (count-- == 0)
                    break;
                writer.WriteLine("{0,12} {1,12}  {2}",
                    s.total_size,
                    s.total_count,
                    s.id);
            }
            writer.WriteLine();
        }

        private static IEnumerable<T> CreateReverseIterator<T>(List<T> list)
        {
            int count = list.Count;
            for (int i = count - 1; i >= 0; --i)
            {
                yield return list[i];
            }
        }


        private class SymbolSourceStats
        {
            public int count;
            public int size;
            public bool singleChild;
        }

        private static void WriteSourceStatsList(TextWriter writer, IEnumerable<KeyValuePair<string, SymbolSourceStats>> statsList, int maxCount, Func<SymbolSourceStats, bool> predicate)
        {
            writer.WriteLine("{0,12}{1,8}  {2}", "Size", "Count", "Source Path");
            int count = maxCount;
            foreach (KeyValuePair<string, SymbolSourceStats> s in statsList)
            {
                if (!predicate(s.Value))
                    continue;
                if (count-- == 0)
                    break;
                writer.WriteLine("{0,12}{1,8}  {2}", s.Value.size, s.Value.count, s.Key == "" ? "[unknown]" : s.Key);
            }
            writer.WriteLine();
        }

        private static void DumpFolderStats(TextWriter writer, List<Symbol> symbolList, int maxCount, bool showDifferences)
        {
            Dictionary<string, SymbolSourceStats> sourceStats = new Dictionary<string, SymbolSourceStats>();
            int childCount = 0;
            foreach (Symbol s in symbolList)
            {
                string filename = s.source_filename;
                for ( ; ; )
                {
                    SymbolSourceStats stat;
                    if (sourceStats.ContainsKey(filename))
                    {
                        stat = sourceStats[filename];
                    }
                    else
                    {
                        stat = new SymbolSourceStats();
                        stat.count = 0;
                        stat.size = 0;
                        stat.singleChild = false;
                        sourceStats.Add(filename, stat);
                    }
                    stat.count += s.count;
                    stat.size += s.size;
                    stat.singleChild = (stat.count == childCount);
                    childCount = stat.count;

                    int searchPos = filename.LastIndexOf('\\');
                    if (searchPos < 0)
                        break;
                    filename = filename.Remove(searchPos);
                }
            }

            List<KeyValuePair<string, SymbolSourceStats>> sortedStats = sourceStats.ToList();
            sortedStats.Sort(
                delegate(KeyValuePair<string, SymbolSourceStats> s0, KeyValuePair<string, SymbolSourceStats> s1)
                {
                    return s1.Value.size - s0.Value.size;
                } );

            writer.WriteLine("File Contributions");
            writer.WriteLine("--------------------------------------");

            if (showDifferences)
            {
                writer.WriteLine("Increases in Size");
                WriteSourceStatsList(writer, sortedStats, maxCount,
                    delegate(SymbolSourceStats s)
                    {
                        return !s.singleChild && s.size > 0;
                    });
                writer.WriteLine("Decreases in Size");
                WriteSourceStatsList(writer, CreateReverseIterator(sortedStats), maxCount,
                    delegate(SymbolSourceStats s)
                    {
                        return !s.singleChild && s.size < 0;
                    });
            }
            else
            {
                writer.WriteLine("Sorted by Size");
                WriteSourceStatsList(writer, sortedStats, maxCount,
                    delegate(SymbolSourceStats s)
                    {
                        return !s.singleChild;
                    });
            }


            sortedStats.Sort(
                delegate(KeyValuePair<string, SymbolSourceStats> s0, KeyValuePair<string, SymbolSourceStats> s1)
                {
                    return String.Compare(s0.Key, s1.Key);
                } );
            writer.WriteLine("Sorted by Path");
            writer.WriteLine("{0,12}{1,8}  {2}", "Size", "Count", "Source Path");
            foreach (KeyValuePair<string, SymbolSourceStats> s in sortedStats)
            {
                if (s.Value.size != 0 || s.Value.count != 0)
                {
                    writer.WriteLine("{0,12}{1,8}  {2}", s.Value.size, s.Value.count, s.Key == "" ? "[unknown]" : s.Key);
                }
            }
            writer.WriteLine();

        }

        static void GetCollatedSymbols(List<Symbol> symbols, List<MergedSymbol> mergedSymbols, Func<Symbol, string[]> collationFunc)
        {
            Dictionary<string, MergedSymbol> dictionary = new Dictionary<string, MergedSymbol>();
            foreach (Symbol s in symbols)
            {
                string[] collatedNames = collationFunc(s);
                foreach (string mergeName in collatedNames)
                {
                    MergedSymbol ss;
                    if (dictionary.TryGetValue(mergeName, out ss))
                    {
                        ss.total_count += s.count;
                        ss.total_size += s.size;
                    }
                    else
                    {
                        ss = new MergedSymbol();
                        ss.id = mergeName;
                        ss.total_count = s.count;
                        ss.total_size = s.size;
                        dictionary.Add(mergeName, ss);
                        mergedSymbols.Add(ss);
                    }
                }
            }
        }

        private static void DumpMergedSymbols(TextWriter writer, List<Symbol> symbols, Func<Symbol, string[]> collationFunc, int maxCount, bool showDifferences)
        {
            List<MergedSymbol> mergedSymbols = new List<MergedSymbol>();
            GetCollatedSymbols(symbols, mergedSymbols, collationFunc);

            writer.WriteLine("Merged Count  : {0}", mergedSymbols.Count);
            writer.WriteLine("--------------------------------------");

            {
                mergedSymbols.Sort(
                    delegate(MergedSymbol s0, MergedSymbol s1)
                    {
                        if (s0.total_count == s1.total_count)
                        {
                            return s1.total_size - s0.total_size;
                        }
                        return s1.total_count - s0.total_count;
                    } );

                if (showDifferences)
                {
                    writer.WriteLine("Increases in Total Count");
                    WriteMergedSymbolList(writer, mergedSymbols, maxCount,
                        delegate(MergedSymbol s)
                        {
                            return s.total_count > 0;
                        } );
                    writer.WriteLine("Decreases in Total Count");
                    WriteMergedSymbolList(writer, CreateReverseIterator(mergedSymbols), maxCount,
                        delegate(MergedSymbol s)
                        {
                            return s.total_count < 0;
                        } );
                }
                else
                {
                    writer.WriteLine("Sorted by Total Count");
                    WriteMergedSymbolList(writer, mergedSymbols, maxCount, 
                        delegate(MergedSymbol s)
                        {
                            return s.total_count != 1;
                        } );
                }
            }

            {
                mergedSymbols.Sort(
                    delegate(MergedSymbol s0, MergedSymbol s1)
                    {
                        return s1.total_size - s0.total_size;
                    } );

                if (showDifferences)
                {
                    writer.WriteLine("Increases in Total Size");
                    WriteMergedSymbolList(writer, mergedSymbols, maxCount,
                        delegate(MergedSymbol s)
                        {
                            return s.total_size > 0;
                        });
                    writer.WriteLine("Decreases in Total Size");
                    WriteMergedSymbolList(writer, CreateReverseIterator(mergedSymbols), maxCount,
                        delegate(MergedSymbol s)
                        {
                            return s.total_size < 0;
                        });
                }
                else
                {
                    writer.WriteLine("Sorted by Total Size");
                    WriteMergedSymbolList(writer, mergedSymbols, maxCount,
                        delegate(MergedSymbol s)
                        {
                            return s.total_count != 1;
                        });
                }
            }
            writer.WriteLine();
        }

        private static void LoadSymbols(InputFile inputFile, List<Symbol> symbols, string searchPath)
        {
            Console.WriteLine("Loading symbols from {0}", inputFile.filename);
            switch (inputFile.type)
            {
                case InputType.pdb:
                    ReadSymbolsFromPDB(symbols, inputFile.filename, searchPath);
                    break;
                case InputType.comdat:
                    ReadSymbolsFromCOMDAT(symbols, inputFile.filename);
                    break;
                case InputType.nm_bsd:
                case InputType.nm_sysv:
                    ReadSymbolsFromNM(symbols , inputFile.filename, inputFile.type);
                    break;
            }
        }

        private static bool ParseArgs(
            string[] args, 
            out List<InputFile> inputFiles, 
            out string outFilename, 
            out List<InputFile> differenceFiles,
            out string searchPath,
            out int maxCount, 
            out List<string> exclusions)
        {
            maxCount = 500;
            exclusions = new List<string>();
            inputFiles = new List<InputFile>();
            outFilename = null;
            differenceFiles = new List<InputFile>();
            searchPath = null;

            if (args.Length < 1)
                return false;

            uint curArg = 0;
            for (curArg = 0; curArg < args.Length - 1; ++curArg)
            {
                string curArgStr = args[curArg].ToLower();
                if (curArgStr == "-count")
                {
                    try
                    {
                        maxCount = int.Parse(args[++curArg]);
                    }
                    catch (System.FormatException)
                    {
                        return false;
                    }
                }
                else if (curArgStr == "-exclude")
                {
                    exclusions.Add(args[++curArg]);
                }
                else if (curArgStr == "-in")
                {
                    inputFiles.Add(new InputFile(args[++curArg], InputType.pdb));
                }
                else if (curArgStr == "-in:comdat")
                {
                    inputFiles.Add(new InputFile(args[++curArg], InputType.comdat));
                }
                else if (curArgStr == "-in:sysv")
                {
                    inputFiles.Add(new InputFile(args[++curArg], InputType.nm_sysv));
                }
                else if (curArgStr == "-in:bsd")
                {
                    inputFiles.Add(new InputFile(args[++curArg], InputType.nm_bsd));
                }
                else if (curArgStr == "-out")
                {
                    outFilename = args[++curArg];
                }
                else if (curArgStr == "-diff")
                {
                    differenceFiles.Add(new InputFile(args[++curArg], InputType.pdb));
                }
                else if (curArgStr == "-diff:comdat")
                {
                    differenceFiles.Add(new InputFile(args[++curArg], InputType.comdat));
                }
                else if (curArgStr == "-diff:sysv")
                {
                    differenceFiles.Add(new InputFile(args[++curArg], InputType.nm_sysv));
                }
                else if (curArgStr == "-diff:bsd")
                {
                    differenceFiles.Add(new InputFile(args[++curArg], InputType.nm_bsd));
                }
                else if (curArgStr == "-searchpath")
                {
                    searchPath = args[++curArg];
                }
                else
                {
                    Console.WriteLine("Unrecognized option {0}", args[curArg]);
                    return false;
                }
            }

            if (!inputFiles.Any())
            {
                Console.WriteLine("At least one input file must be specified");
                return false;
            }

            return true;
        }

        static void Main(string[] args)
        {
            int maxCount;
            List<string> exclusions;
            List<InputFile> inputFiles;
            List<InputFile> differenceFiles;
            string outFilename;
            string searchPath;
            if (!ParseArgs(args, out inputFiles, out outFilename, out differenceFiles, out searchPath, out maxCount, out exclusions))
            {
                Console.WriteLine();
                Console.WriteLine("Usage: SymbolSort [options]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("  -in[:type] filename");
                Console.WriteLine("      Specify an input file with optional type.  Exe and PDB files are");
                Console.WriteLine("      identified automatically by extension.  Otherwise type may be:");
                Console.WriteLine("          comdat - the format produced by DumpBin /headers");
                Console.WriteLine("          sysv   - the format produced by nm --format=sysv");
                Console.WriteLine("          bsd    - the format produced by nm --format=bsd --print-size");
                Console.WriteLine();
                Console.WriteLine("  -out filename");
                Console.WriteLine("      Write output to specified file instead of stdout");
                Console.WriteLine();
                Console.WriteLine("  -count num_symbols");
                Console.WriteLine("      Limit the number of symbols displayed to num_symbols");
                Console.WriteLine();
                Console.WriteLine("  -exclude substring");
                Console.WriteLine("      Exclude symbols that contain the specified substring");
                Console.WriteLine();
                Console.WriteLine("  -diff:[type] filename");
                Console.WriteLine("      Use this file as a basis for generating a differences report.");
                Console.WriteLine("      See -in option for valid types.");
                Console.WriteLine();
                Console.WriteLine("  -searchpath path");
                Console.WriteLine("      Specify the symbol search path when loading an exe");
                return;
            }

            foreach (InputFile inputFile in inputFiles)
            {
                if (!File.Exists(inputFile.filename))
                {
                    Console.WriteLine("Input file {0} does not exist!", inputFile.filename);
                    return;
                }
            }

            foreach (InputFile inputFile in differenceFiles)
            {
                if (!File.Exists(inputFile.filename))
                {
                    Console.WriteLine("Difference file {0} does not exist!", inputFile.filename);
                    return;
                }
            }

            TextWriter writer;
            try
            {
                writer = outFilename != null ? new StreamWriter(outFilename) : Console.Out;
            }
            catch (IOException ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

            DateTime startTime = DateTime.Now;

            List<Symbol> symbols = new List<Symbol>();
            foreach (InputFile inputFile in inputFiles)
            {
                LoadSymbols(inputFile, symbols, searchPath);
                Console.WriteLine();
            }

            foreach (InputFile inputFile in differenceFiles)
            {
                List<Symbol> negativeSymbols = new List<Symbol>();
                LoadSymbols(inputFile, negativeSymbols, searchPath);
                Console.WriteLine();
                foreach (Symbol s in negativeSymbols)
                {
                    s.size = -s.size;
                    s.count = -s.count;
                    symbols.Add(s);
                }
            }

            if (exclusions.Any())
            {
                Console.WriteLine("Removing Exclusions...");
                symbols.RemoveAll(
                    delegate(Symbol s)
                    {
                        foreach (string e in exclusions)
                        {
                            if (s.name.Contains(e))
                                return true;
                        }
                        return false;
                    });
            }

            Console.WriteLine("Processing raw symbols...");
            {
                long totalCount = 0;
                long totalSize = 0;

                foreach (Symbol s in symbols)
                {
                    totalSize += s.size;
                    totalCount += s.count;
                }

                if (differenceFiles.Any())
                {
                    writer.WriteLine("Raw Symbols Differences");
                    writer.WriteLine("Total Count : {0}", totalCount);
                    writer.WriteLine("Total Size  : {0}", totalSize);
                    writer.WriteLine();
                }
                else
                {
                    writer.WriteLine("Raw Symbols");
                    writer.WriteLine("Total Count : {0}", totalCount);
                    writer.WriteLine("Total Size  : {0}", totalSize);
                    writer.WriteLine("--------------------------------------");
                    symbols.Sort(
                        delegate(Symbol s0, Symbol s1)
                        {
                            return s1.size - s0.size;
                        });
                    writer.WriteLine("Sorted by Size");
                    WriteSymbolList(writer, symbols, maxCount);
                }
            }

            Console.WriteLine("Building folder stats...");
            DumpFolderStats(writer, symbols, maxCount, differenceFiles.Any());

            Console.WriteLine("Computing section stats...");
            writer.WriteLine("Merged Sections / Types");
            DumpMergedSymbols(
                writer,
                symbols,
                delegate(Symbol s)
                {
                    return new string[] { s.section };
                },
                maxCount,
                differenceFiles.Any());

            Console.WriteLine("Merging duplicate symbols...");
            writer.WriteLine("Merged Duplicate Symbols");
            DumpMergedSymbols(
                writer,
                symbols,
                delegate(Symbol s)
                {
                    return new string[] { s.name };
                },
                maxCount,
                differenceFiles.Any());

            Console.WriteLine("Merging template symbols...");
            writer.WriteLine("Merged Template Symbols");
            DumpMergedSymbols(
                writer,
                symbols,
                delegate(Symbol s)
                {
                    string n = s.name;
                    n = ExtractGroupedSubstrings(n, '<', '>', "T");
                    n = ExtractGroupedSubstrings(n, '\'', '\'', "...");
                    return new string[] { n };
                },
                maxCount,
                differenceFiles.Any());

            Console.WriteLine("Merging overloaded symbols...");
            writer.WriteLine("Merged Overloaded Symbols");
            DumpMergedSymbols(
                writer,
                symbols,
                delegate(Symbol s)
                {
                    string n = s.short_name;
                    n = ExtractGroupedSubstrings(n, '<', '>', "T");
                    n = ExtractGroupedSubstrings(n, '\'', '\'', "...");
                    n = ExtractGroupedSubstrings(n, '(', ')', "...");
                    return new string[] { n };
                },
                maxCount,
                differenceFiles.Any());

            Console.WriteLine("Building tag cloud...");
            writer.WriteLine("Symbol Tags");
            DumpMergedSymbols(
                writer,
                symbols,
                delegate(Symbol s)
                {
                    return s.name.Split(" ,.&*()<>:'`".ToArray(), StringSplitOptions.RemoveEmptyEntries);
                },
                maxCount,
                differenceFiles.Any());
            writer.Close();

            Console.WriteLine("Elapsed Time: {0}", (DateTime.Now - startTime));
        }
    }
}
