#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
using namespace std;

struct PESection { char name[8]; uint32_t vsize; uint32_t rva; uint32_t rawsize; uint32_t rawoff; };

static bool readAll(const string& p, vector<uint8_t>& d){ ifstream f(p, ios::binary); if(!f) return false; f.seekg(0, ios::end); size_t n=f.tellg(); f.seekg(0); d.resize(n); f.read((char*)d.data(), n); return true; }

static uint64_t fnv1a64(const vector<uint8_t>& v){ uint64_t h=0xCBF29CE484222325ULL; for(uint8_t c:v){ h^=c; h*=0x100000001B3ULL; } return h; }
static int32_t eLfanew(const vector<uint8_t>& d){ return *(int32_t*)&d[0x3c]; }

int main(int argc, char** argv){
    if(argc<3){ printf("usage: verify_unpack original.exe packed.exe\n"); return 1; }
    vector<uint8_t> a,b; if(!readAll(argv[1],a)||!readAll(argv[2],b)){ printf("read failed\n"); return 1; }
    int32_t pa=eLfanew(a), pb=eLfanew(b);
    uint16_t na=*(uint16_t*)&a[pa+6], nb=*(uint16_t*)&b[pb+6];
    uint32_t seca=pa+24+*(uint16_t*)&a[pa+20];
    uint32_t secb=pb+24+*(uint16_t*)&b[pb+20];
    // find original .text and packed .np_data
    vector<uint8_t> text; vector<uint8_t> packed; uint32_t keyOff=0; uint32_t recOff=0;
    for(int i=0;i<na;i++){ const uint8_t* p=&a[seca+i*40]; const char* nm=(const char*)p; if(!strncmp(nm,".text",8)){ uint32_t off=*(uint32_t*)&p[20]; uint32_t sz=*(uint32_t*)&p[16]; text.assign(a.begin()+off, a.begin()+off+sz); } }
    for(int i=0;i<nb;i++){ const uint8_t* p=&b[secb+i*40]; const char* nm=(const char*)p; if(!strncmp(nm,".np_data",8)){ uint32_t off=*(uint32_t*)&p[20]; uint32_t sz=*(uint32_t*)&p[16]; packed.assign(b.begin()+off, b.begin()+off+sz); } }
    if(text.empty()||packed.size()<96){ printf("missing data\n"); return 1; }
    uint32_t magic=*(uint32_t*)&packed[0];
    uint32_t version=*(uint32_t*)&packed[4];
    if(magic!=0x41564F4E){ printf("bad magic 0x%08X\n", magic); return 1; }
    if(version!=3){ printf("unsupported payload version %u\n", version); return 1; }
    uint32_t count=*(uint32_t*)&packed[8];
    const uint8_t* key=&packed[16];
    recOff=96;
    const uint8_t* payload=&packed[recOff+32*count];
    for(uint32_t r=0;r<count;r++){
        const uint8_t* rec=&packed[recOff+32*r];
        uint32_t rva=*(uint32_t*)&rec[0];
        uint32_t origSize=*(uint32_t*)&rec[4];
        uint32_t stored=*(uint32_t*)&rec[8];
        uint32_t flags=*(uint32_t*)&rec[12];
        printf("region %u rva=0x%X orig=0x%X stored=0x%X flags=%u\n", r, rva, origSize, stored, flags);
        vector<uint8_t> src(payload, payload+stored); payload += (stored+7)&~7;
        for(uint32_t k=0;k<stored;k++) src[k]^=key[k%32];
        vector<uint8_t> out;
        if(flags&1){
            size_t ip=0; out.reserve(origSize);
            while(out.size()<origSize && ip<src.size()){
                uint8_t t=src[ip++];
                if(t&0x80){ uint32_t len=(t&0x7f)+1; uint8_t v=src[ip++]; out.insert(out.end(), len, v); }
                else { uint32_t len=t+1; out.insert(out.end(), src.begin()+ip, src.begin()+ip+len); ip+=len; }
            }
        } else out=src;
        if(flags&2){
            uint64_t want=*(uint64_t*)&rec[16];
            uint64_t got=fnv1a64(out);
            if(got!=want){ printf("integrity FAIL rva=0x%X got=%016llX want=%016llX\n", rva, got, want); return 1; }
            printf("integrity OK\n");
        }
        if(rva==0x1000){
            if(out.size()>text.size()){ printf("restored too large\n"); return 1; }
            size_t mm=0; for(size_t j=0;j<out.size() && j<text.size();j++) if(out[j]!=text[j]) { mm=j; break; }
            if(mm<out.size() && mm<text.size() && out[mm]!=text[mm]){
                printf("MISMATCH at 0x%zX: packed=0x%02X orig=0x%02X\n", mm, out[mm], text[mm]);
                for(size_t j=0;j<16;j++) printf("%02X ", out[j]); printf("\n");
                for(size_t j=0;j<16;j++) printf("%02X ", text[j]); printf("\n");
                return 1;
            } else printf("text OK\n");
        }
    }
    return 0;
}

