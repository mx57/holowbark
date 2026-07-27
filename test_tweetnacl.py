# Let's write the exact TweetNaCl C code for M:
# void M(gf o,const gf a,const gf b) {
#   i64 i,j,t[31];
#   FOR(i,31) t[i]=0;
#   FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
#   FOR(i,15) t[i]+=38*t[i+16];
#   FOR(i,16) o[i]=t[i];
#   car25519(o);
#   car25519(o);
# }
