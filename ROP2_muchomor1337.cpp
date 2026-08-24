#include <windows.h>
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
static uint32_t get32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
static void put32(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }
static uint32_t align_up(uint32_t n, uint32_t a) { return (n + a - 1) & ~(a - 1); }

static std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0); WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr); return s;
}
static std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    if (!n) { std::wstring w; for (unsigned char c : s) w.push_back(c); return w; }
    std::wstring w(n, 0); MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n); return w;
}
static std::string hex_encode(const std::string& s) {
    static const char h[]="0123456789ABCDEF"; std::string o; o.reserve(s.size()*2);
    for (uint8_t c : s) { o.push_back(h[c>>4]); o.push_back(h[c&15]); } return o;
}
static std::string hex_decode(const std::string& s) {
    auto v=[](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='A'&&c<='F')return c-'A'+10; if(c>='a'&&c<='f')return c-'a'+10; return -1; };
    if (s.size()%2) throw Error("Invalid manifest (hex)"); std::string o(s.size()/2,0);
    for(size_t i=0;i<o.size();++i){int a=v(s[i*2]),b=v(s[i*2+1]);if(a<0||b<0)throw Error("Invalid manifest (hex)");o[i]=char((a<<4)|b);}return o;
}
static std::vector<std::string> split_tab(const std::string& s) {
    std::vector<std::string> v; size_t a=0; for(;;){size_t b=s.find('\t',a);v.push_back(s.substr(a,b-a));if(b==std::string::npos)return v;a=b+1;}
}
static Bytes read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary); if(!f) throw Error("Cannot read: "+narrow(p.wstring()));
    f.seekg(0,std::ios::end); auto n=f.tellg(); if(n<0)throw Error("Cannot determine file size"); f.seekg(0);
    Bytes b((size_t)n); if(!b.empty()&&!f.read((char*)b.data(),b.size()))throw Error("Read error: "+narrow(p.wstring())); return b;
}
static Bytes read_at(const fs::path& p, uint32_t pos, uint32_t size) {
    std::ifstream f(p,std::ios::binary);if(!f)throw Error("Cannot read: "+narrow(p.wstring()));f.seekg(pos);
    Bytes b(size);if(size&&!f.read((char*)b.data(),size))throw Error("Invalid data range in: "+narrow(p.wstring()));return b;
}
static void write_file(const fs::path& p, const Bytes& b) {
    fs::create_directories(p.parent_path());std::ofstream f(p,std::ios::binary|std::ios::trunc);if(!f)throw Error("Cannot write: "+narrow(p.wstring()));
    if(!b.empty())f.write((const char*)b.data(),b.size());if(!f)throw Error("Write error: "+narrow(p.wstring()));
}
static uint32_t crc32(const uint8_t* p,size_t n){static uint32_t tab[256];static bool init=false;if(!init){for(uint32_t i=0;i<256;i++){uint32_t c=i;for(int j=0;j<8;j++)c=(c>>1)^(0xEDB88320u&-(int)(c&1));tab[i]=c;}init=true;}uint32_t c=~0u;while(n--)c=tab[(c^*p++)&255]^(c>>8);return ~c;}

static constexpr const wchar_t* APP_CLIENT=L"ROP2.RO v3.0";
static constexpr const wchar_t* APP_SHORT=L"ROP2";
static constexpr const char* APP_TITLE="ROP2 muchomor1337";
static constexpr const char* FORMAT_ID="rop2";
static constexpr std::array<uint8_t,4> OBJECT_MAGIC{'0','6','3','9'};

class AesCfb {
    BCRYPT_ALG_HANDLE alg{}; BCRYPT_KEY_HANDLE key{}; Bytes key_object;
    std::array<uint8_t,16> iv{0xCA,0x77,0x41,0x1C,0xD4,0x02,0xE1,0xBD,0xB5,0x58,0x3A,0xE5,0xDF,0x2F,0xF6,0x2B};
public:
    AesCfb(){std::array<uint8_t,16> kb{0x26,0x7B,0xF0,0xE5,0xF6,0x20,0xFD,0x0A,0xE7,0x73,0xD8,0x38,0x5C,0x54,0xB6,0x64};DWORD cb=0,got=0,block=16;
        if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,nullptr,0)<0)throw Error("BCrypt AES");
        if(BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CFB,sizeof(BCRYPT_CHAIN_MODE_CFB),0)<0)throw Error("BCrypt CFB");
        BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&cb,sizeof(cb),&got,0);key_object.resize(cb);
        if(BCryptGenerateSymmetricKey(alg,&key,key_object.data(),cb,kb.data(),kb.size(),0)<0)throw Error("BCrypt key");
        if(BCryptSetProperty(key,BCRYPT_MESSAGE_BLOCK_LENGTH,(PUCHAR)&block,sizeof(block),0)<0)throw Error("BCrypt block");}
    ~AesCfb(){if(key)BCryptDestroyKey(key);if(alg)BCryptCloseAlgorithmProvider(alg,0);}
    Bytes crypt(const uint8_t* src,uint32_t meaningful,bool encrypt){uint32_t bulk=align_up(meaningful,16);Bytes in(bulk),out(bulk);std::memcpy(in.data(),src,meaningful);auto ivcopy=iv;DWORD got=0;NTSTATUS st=encrypt?BCryptEncrypt(key,in.data(),bulk,nullptr,ivcopy.data(),ivcopy.size(),out.data(),bulk,&got,0):BCryptDecrypt(key,in.data(),bulk,nullptr,ivcopy.data(),ivcopy.size(),out.data(),bulk,&got,0);if(st<0||got!=bulk)throw Error("AES-CFB error");return out;}
};

static bool lz4_decompress(const uint8_t*in,size_t n,uint8_t*out,size_t cap,size_t&os){const uint8_t*ip=in,*ie=in+n;uint8_t*op=out,*oe=out+cap;while(ip<ie){uint8_t tok=*ip++;size_t lit=tok>>4;if(lit==15){uint8_t x;do{if(ip>=ie)return false;x=*ip++;lit+=x;}while(x==255);}if(ip+lit>ie||op+lit>oe)return false;std::memcpy(op,ip,lit);ip+=lit;op+=lit;if(ip==ie){os=op-out;return true;}if(ip+2>ie)return false;size_t off=ip[0]|(size_t(ip[1])<<8);ip+=2;if(!off||off>size_t(op-out))return false;size_t len=(tok&15)+4;if((tok&15)==15){uint8_t x;do{if(ip>=ie)return false;x=*ip++;len+=x;}while(x==255);}if(op+len>oe)return false;while(len--){*op=op[-(ptrdiff_t)off];op++;}}os=op-out;return true;}
static Bytes lz4_compress_literal(const Bytes&raw){Bytes o;size_t n=raw.size();o.push_back(uint8_t(std::min<size_t>(15,n)<<4));if(n>=15){size_t r=n-15;while(r>=255){o.push_back(255);r-=255;}o.push_back((uint8_t)r);}o.insert(o.end(),raw.begin(),raw.end());return o;}

static Bytes decode_object(const Bytes&obj,AesCfb&aes){if(obj.size()<20)throw Error("Object is too short");if(std::memcmp(obj.data(),OBJECT_MAGIC.data(),4))throw Error("Invalid object signature");uint32_t enc=get32(obj.data()+4),comp=get32(obj.data()+8),real=get32(obj.data()+12);if(obj.size()<20ull+enc||comp+4ull>enc)throw Error("Corrupted object header");Bytes plain=aes.crypt(obj.data()+16,comp+4,false);if(std::memcmp(plain.data(),OBJECT_MAGIC.data(),4))throw Error("Invalid key or inner signature");Bytes raw(real);size_t out=0;if(!lz4_decompress(plain.data()+4,comp,raw.data(),raw.size(),out)||out!=real)throw Error("Decompression error");return raw;}
static Bytes encode_object(const Bytes&raw,AesCfb&aes){Bytes comp=lz4_compress_literal(raw);if(comp.size()>0xFFFFFF00ull||raw.size()>0xFFFFFFFFull)throw Error("File is too large (>4 GB)");uint32_t cs=(uint32_t)comp.size(),enc=align_up(cs+19,8),meaningful=cs+4;Bytes plain(align_up(meaningful,16));std::memcpy(plain.data(),OBJECT_MAGIC.data(),4);std::memcpy(plain.data()+4,comp.data(),comp.size());Bytes cipher=aes.crypt(plain.data(),meaningful,true);Bytes obj(20ull+enc);std::memcpy(obj.data(),OBJECT_MAGIC.data(),4);put32(obj.data()+4,enc);put32(obj.data()+8,cs);put32(obj.data()+12,(uint32_t)raw.size());std::memcpy(obj.data()+16,cipher.data(),std::min<size_t>(cipher.size(),enc));return obj;}

static std::string safe_local(const std::string& raw,uint32_t id){std::string s=raw;std::replace(s.begin(),s.end(),'\\','/');if(s.size()>2&&std::isalpha((unsigned char)s[0])&&s[1]==':')s.erase(0,2);while(!s.empty()&&s[0]=='/')s.erase(s.begin());std::vector<std::string> parts;std::stringstream ss(s);std::string part;while(std::getline(ss,part,'/')){if(part.empty()||part==".")continue;if(part=="..")part="_UP_";std::string q;for(unsigned char c:part){if(c<32||c>=127||std::strchr("<>:\"|?*",c)){char b[4];std::snprintf(b,sizeof(b),"_%02X",c);q+=b;}else q.push_back((char)c);}while(!q.empty()&&(q.back()=='.'||q.back()==' '))q.pop_back();if(q.empty())q="_";if(q.size()>150)q=q.substr(0,130)+"__"+std::to_string(id);parts.push_back(q);}if(parts.empty())parts.push_back("file_"+std::to_string(id));std::string o;for(auto&p:parts){if(!o.empty())o+='/';o+=p;}return o;}

#pragma pack(push,1)
struct Entry {uint32_t id;char name[161];uint8_t pad_name[3];uint32_t filename_crc;uint32_t allocation_size;uint32_t data_size;uint32_t data_crc;uint32_t position;uint8_t type;uint8_t pad[3];};
#pragma pack(pop)
static_assert(sizeof(Entry)==192);
struct ManifestEntry{uint32_t id,type,name_crc;std::string virtual_name,local;};
static constexpr const wchar_t* MANIFEST_NAME=L"muchomor1337.tsv";

static std::vector<Entry> read_index(const fs::path&eix,AesCfb&aes){Bytes obj=read_file(eix),raw=decode_object(obj,aes);if(raw.size()<12||std::memcmp(raw.data(),"EPKD",4)||get32(raw.data()+4)!=2)throw Error("Unknown ROP2 index: "+narrow(eix.wstring()));uint32_t count=get32(raw.data()+8);if(12ull+192ull*count!=raw.size())throw Error("Invalid index size: "+narrow(eix.wstring()));std::vector<Entry> v(count);std::memcpy(v.data(),raw.data()+12,count*192ull);return v;}
static void write_manifest(const fs::path&p,const std::string&archive,const std::vector<ManifestEntry>&v){std::ofstream f(p,std::ios::binary|std::ios::trunc);if(!f)throw Error("Cannot write manifest");f<<"# muchomor1337 manifest v1\nP\t"<<FORMAT_ID<<"\t"<<archive<<"\n";for(auto&e:v)f<<"E\t"<<e.id<<'\t'<<e.type<<'\t'<<e.name_crc<<'\t'<<hex_encode(e.virtual_name)<<'\t'<<hex_encode(e.local)<<"\n";}
static std::pair<std::string,std::vector<ManifestEntry>> read_manifest(const fs::path&p){std::ifstream f(p,std::ios::binary);if(!f)throw Error("Manifest is missing");std::string line,archive;std::vector<ManifestEntry> v;while(std::getline(f,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.empty()||line[0]=='#')continue;auto a=split_tab(line);if(a[0]=="P"){if(a.size()!=3||a[1]!=FORMAT_ID)throw Error("This is not a ROP2 manifest");archive=a[2];}else if(a[0]=="E"){if(a.size()!=6)throw Error("Corrupted manifest");ManifestEntry e;e.id=std::stoul(a[1]);e.type=std::stoul(a[2]);e.name_crc=std::stoul(a[3]);e.virtual_name=hex_decode(a[4]);e.local=hex_decode(a[5]);v.push_back(std::move(e));}}if(archive.empty())throw Error("Corrupted manifest format");return {archive,v};}

static void unpack_one(const fs::path&eix,const fs::path&out,AesCfb&aes){fs::path epk=eix;epk.replace_extension(L".epk");if(!fs::exists(epk))throw Error("Matching EPK is missing: "+narrow(epk.wstring()));std::string archive=narrow(eix.stem().wstring());fs::path dir=out/widen(safe_local(archive,0));fs::create_directories(dir);auto entries=read_index(eix,aes);std::vector<ManifestEntry> man;man.reserve(entries.size());std::unordered_set<std::string> used;uint32_t done=0;
    for(auto&e:entries){size_t nl=0;while(nl<sizeof(e.name)&&e.name[nl])nl++;std::string virt(e.name,e.name+nl),local=safe_local(virt,e.id);if(!used.insert(local).second){local+="__"+std::to_string(e.id);used.insert(local);}fs::path target=dir/widen(local);Bytes stored=read_at(epk,e.position,e.data_size);if(e.type!=32)throw Error("Unsupported ROP2 entry type: "+std::to_string(e.type));Bytes raw=decode_object(stored,aes);write_file(target,raw);man.push_back({e.id,e.type,e.filename_crc,virt,local});if((++done%5000)==0)std::cout<<"  "<<done<<" / "<<entries.size()<<"\n";}
    write_manifest(dir/MANIFEST_NAME,archive,man);std::cout<<"OK  "<<archive<<"  ("<<entries.size()<<" files)\n";}
static void unpack_all(const fs::path&pack,const fs::path&out){fs::create_directories(out);AesCfb aes;std::vector<fs::path> ix;for(auto&d:fs::directory_iterator(pack))if(d.is_regular_file()&&d.path().extension()==L".eix")ix.push_back(d.path());std::sort(ix.begin(),ix.end());if(ix.empty())throw Error("No .eix files were found");std::cout<<"Archives: "<<ix.size()<<"\n";size_t n=0;for(auto&x:ix){std::cout<<"["<<++n<<"/"<<ix.size()<<"] "<<narrow(x.stem().wstring())<<"\n";unpack_one(x,out,aes);}std::cout<<"DONE: "<<ix.size()<<" archives\n";}

static void pack_one(const fs::path&dir,const fs::path&out,AesCfb&aes){auto [archive,man]=read_manifest(dir/MANIFEST_NAME);fs::create_directories(out);fs::path epk=out/widen(archive+".epk"),eix=out/widen(archive+".eix");std::ofstream data(epk,std::ios::binary|std::ios::trunc);if(!data)throw Error("Cannot write EPK");std::vector<Entry> entries;entries.reserve(man.size());uint64_t pos=0;uint32_t done=0;
    for(auto&m:man){if(m.type!=32)throw Error("Unsupported ROP2 entry type: "+std::to_string(m.type));Bytes raw=read_file(dir/widen(m.local)),stored=encode_object(raw,aes);if(pos>0xFFFFFFFFull||stored.size()>0xFFFFFFFFull)throw Error("Archive exceeded the 4 GB limit");Entry e{};e.id=m.id;std::memcpy(e.name,m.virtual_name.data(),std::min(m.virtual_name.size(),sizeof(e.name)-1));e.filename_crc=m.name_crc;e.data_size=(uint32_t)stored.size();e.allocation_size=align_up(e.data_size,256);e.data_crc=crc32(stored.data(),stored.size());e.position=(uint32_t)pos;e.type=(uint8_t)m.type;data.write((char*)stored.data(),stored.size());Bytes zero(e.allocation_size-e.data_size);if(!zero.empty())data.write((char*)zero.data(),zero.size());if(!data)throw Error("EPK write error");pos+=e.allocation_size;entries.push_back(e);if((++done%5000)==0)std::cout<<"  "<<done<<" / "<<man.size()<<"\n";}
    Bytes idx(12ull+entries.size()*192ull);std::memcpy(idx.data(),"EPKD",4);put32(idx.data()+4,2);put32(idx.data()+8,(uint32_t)entries.size());std::memcpy(idx.data()+12,entries.data(),entries.size()*192ull);write_file(eix,encode_object(idx,aes));std::cout<<"OK  "<<archive<<"  ("<<entries.size()<<" files)\n";}
static void pack_all(const fs::path&unpacked,const fs::path&out){fs::create_directories(out);AesCfb aes;std::vector<fs::path> dirs;for(auto&d:fs::directory_iterator(unpacked))if(d.is_directory()&&fs::exists(d.path()/MANIFEST_NAME))dirs.push_back(d.path());std::sort(dirs.begin(),dirs.end());if(dirs.empty())throw Error("No manifests were found. Run unpacking first.");std::cout<<"Archives: "<<dirs.size()<<"\n";size_t n=0;for(auto&d:dirs){std::cout<<"["<<++n<<"/"<<dirs.size()<<"] "<<narrow(d.filename().wstring())<<"\n";pack_one(d,out,aes);}std::cout<<"DONE: "<<dirs.size()<<" archives\n";}

static void usage(){std::cout<<APP_TITLE<<"\n\n  application.exe unpack-all <pack_folder> <output_folder>\n  application.exe pack-all   <unpacked_folder> <output_folder>\n\nRun without arguments to open the interactive menu.\n";}
static fs::path exe_directory(){std::wstring b(32768,L'\0');DWORD n=GetModuleFileNameW(nullptr,b.data(),(DWORD)b.size());b.resize(n);return fs::path(b).parent_path();}
static fs::path ask_path(const std::wstring&label,const fs::path&def){std::wcout<<L"\n"<<label<<L"\n[ENTER = "<<def.wstring()<<L"]\n> ";std::wstring s;std::getline(std::wcin,s);while(!s.empty()&&iswspace(s.back()))s.pop_back();if(s.empty())return def;if(s.size()>=2&&s.front()==L'\"'&&s.back()==L'\"')s=s.substr(1,s.size()-2);return fs::path(s);}
static int panel(){fs::path base=exe_directory();for(;;){std::cout<<"\n========================================\n       "<<APP_TITLE<<"\n========================================\n1. Unpack all archives\n2. Pack all archives\n0. Exit\n\nSelect: ";std::wstring choice;std::getline(std::wcin,choice);while(!choice.empty()&&iswspace(choice.back()))choice.pop_back();if(choice==L"0"||std::wcin.eof())return 0;if(choice!=L"1"&&choice!=L"2"){std::cout<<"Invalid selection.\n";continue;}try{fs::path source_default=base.parent_path()/APP_CLIENT/L"pack";if(!fs::exists(source_default))source_default=base/L"pack";if(!fs::exists(source_default))source_default=base/APP_CLIENT/L"pack";fs::path unpack_default=base/(std::wstring(APP_SHORT)+L"_UNPACKED"),pack_default=base/(std::wstring(APP_SHORT)+L"_PACKED");if(base.filename()==L"ROP2_ROZPAKOWANY"){unpack_default=base/L"UNPACKED";pack_default=base/L"PACKED";}if(choice==L"1"){auto src=ask_path(L"Folder containing the original ROP2 EIX/EPK archives:",source_default);auto dst=ask_path(L"Unpacked output folder:",unpack_default);unpack_all(src,dst);}else{auto src=ask_path(L"Unpacked ROP2 folder containing muchomor1337.tsv files:",unpack_default);auto dst=ask_path(L"Output folder for the new ROP2 EIX/EPK archives:",pack_default);pack_all(src,dst);}}catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";}std::cout<<"\nPress ENTER to return to the menu...";std::wstring x;std::getline(std::wcin,x);}}
int wmain(int argc,wchar_t**argv){try{SetConsoleOutputCP(CP_UTF8);SetConsoleCP(CP_UTF8);if(argc==1)return panel();if(argc!=4){usage();return 2;}std::wstring cmd=argv[1];if(cmd==L"unpack-all")unpack_all(argv[2],argv[3]);else if(cmd==L"pack-all")pack_all(argv[2],argv[3]);else{usage();return 2;}return 0;}catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}}
