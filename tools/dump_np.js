const fs=require('fs');
const b=fs.readFileSync(process.argv[2]);
const e=b.indexOf('PE\0\0'); const opt=e+24; const magic=b.readUInt16LE(opt);
const ddoff=opt+(magic===0x20b?112:96);
const dd=[]; for(let i=0;i<16;i++) dd.push([b.readUInt32LE(ddoff+i*8),b.readUInt32LE(ddoff+i*8+4)]);
console.log({magic:magic.toString(16),ep:b.readUInt32LE(opt+16).toString(16),base:'0x'+b.readBigUInt64LE(opt+24).toString(16),size:b.readUInt32LE(opt+56).toString(16)});
const nsec=b.readUInt16LE(e+6), secoff=opt+b.readUInt16LE(e+20);
for(let i=0;i<nsec;i++){const o=secoff+i*40; console.log(i,b.slice(o,o+8).toString().replace(/\0/g,''),b.readUInt32LE(o+12).toString(16),b.readUInt32LE(o+8).toString(16),b.readUInt32LE(o+16).toString(16),b.readUInt32LE(o+20).toString(16));}
const [rd,rs]=dd[5]; const rvaToOff=(rva)=>{for(let i=0;i<nsec;i++){const o=secoff+i*40; const va=b.readUInt32LE(o+12),vs=Math.max(b.readUInt32LE(o+8),b.readUInt32LE(o+16)),ptr=b.readUInt32LE(o+20); if(rva>=va&&rva<va+vs) return ptr+(rva-va);} return 0;}; console.log('reloc',rd.toString(16),rs.toString(16));
for(let i=0;i<nsec;i++){const o=secoff+i*40; if(b.slice(o,o+8).toString().replace(/\0/g,'')!=='.np_data') continue; const va=b.readUInt32LE(o+12), rs2=b.readUInt32LE(o+16), ptr=b.readUInt32LE(o+20); const p=b.slice(ptr,ptr+rs2); const h=Array.from({length:20},(_,j)=>p.readUInt32LE(j*4)); console.log('data',va.toString(16),rs2.toString(16),ptr.toString(16),h.map(x=>x.toString(16))); const n=h[2]; const recs=[]; for(let j=0;j<n;j++)recs.push([p.readUInt32LE(96+j*16),p.readUInt32LE(100+j*16),p.readUInt32LE(104+j*16),p.readUInt32LE(108+j*16)]); console.log('regions',recs.map(r=>r.map((x,k)=>k===3?x:'0x'+x.toString(16)))); let cur=96+n*16; const blobs=recs.map(r=>{const o2=cur; cur+=Math.ceil(r[2]/8)*8; return {rva:r[0],size:r[1],stored:r[2],off:o2}}); console.log('blobs',blobs); console.log('tls',{orig:h[14].toString(16),new:h[15].toString(16),cap:h[16],count:h[17]}); if(rs){let q=0; while(q<rs){const page=b.readUInt32LE(rvaToOff(rd)+q), size=b.readUInt32LE(rvaToOff(rd)+q+4); if(!size)break; const count=(size-8)/2; console.log('block',page.toString(16),size,count); for(let k=0;k<count;k++){const ent=b.readUInt16LE(rvaToOff(rd)+q+8+k*2), typ=ent>>12, target=page+(ent&0xfff); if(typ) console.log(' ',k,target.toString(16),'type',typ,'in',blobs.filter(x=>target>=x.rva&&target<x.rva+x.size).map(x=>x.rva.toString(16)));} q+=size;}} }



