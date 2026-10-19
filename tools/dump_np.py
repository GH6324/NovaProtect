import struct, sys
fn=sys.argv[1]
b=open(fn,'rb').read()
pe=struct.unpack_from('<I',b,b.find(b'PE\0\0'))[0]
e_lfanew=b.find(b'PE\0\0')
opt=e_lfanew+24
magic=struct.unpack_from('<H',b,opt)[0]
ddoff=opt+(112 if magic==0x20b else 96)
dd=[]
for i in range(16): dd.append(struct.unpack_from('<II',b,ddoff+i*8))
print('magic',hex(magic),'ep',hex(struct.unpack_from('<I',b,opt+16)[0]),'imagebase',hex(struct.unpack_from('<Q',b,opt+24)[0]),'sizeofimage',hex(struct.unpack_from('<I',b,opt+56)[0]))
nsec=struct.unpack_from('<H',b,e_lfanew+6)[0]
secoff=opt+struct.unpack_from('<H',b,e_lfanew+20)[0]
for i in range(nsec):
    off=secoff+i*40
    name=b[off:off+8].rstrip(b'\0').decode(errors='replace')
    vs,va,rs,ptr=struct.unpack_from('<IIII',b,off+8)
    print(i,name,hex(va),hex(vs),hex(rs),hex(ptr))
rd,rs=dd[5]
print('reloc',hex(rd),hex(rs))
# find np_data by name
for i in range(nsec):
    off=secoff+i*40; name=b[off:off+8].rstrip(b'\0')
    if name==b'.np_data':
      va,rs2,ptr=struct.unpack_from('<III',b,off+12)
      p=b[ptr:ptr+rs2]
      h=struct.unpack_from('<12I',p,0)
      print('data',hex(va),hex(rs2),hex(ptr),'header',[hex(x) for x in h])
      n=h[2]
      recs=[]
      for j in range(n): recs.append(struct.unpack_from('<4I',p,96+j*16))
      print('regions',[(hex(a),hex(c),hex(d),e) for a,c,d,e in recs])
      cur=96+n*16
      blobs=[]
      for j,(a,c,d,e) in enumerate(recs): blobs.append((a,c,d,e,cur)); cur+=(d+7)//8*8
      print('blob offsets',[(hex(a),hex(o)) for a,c,d,e,o in blobs])
      print('tls',hex(h[14]),hex(h[15]),h[16],h[17],'newrva',hex(h[16]) if h[15] else None)
      if rs:
        q=0
        while q<rs:
          page,size=struct.unpack_from('<II',b,ptr+rd+q)
          if not size: break
          count=(size-8)//2
          print('block',hex(page),size,count)
          for k in range(count):
            ent=struct.unpack_from('<H',b,ptr+rd+q+8+k*2)[0]
            typ=ent>>12; off2=ent&0xfff; target=page+off2
            inreg=[(hex(a),hex(c)) for a,c,d,e,o in blobs if a<=target<a+c]
            if typ: print(' ',k,hex(target),'type',typ,'in',inreg)
          q+=size
