#include <NTL/ZZ.h>
#include <gcrypt.h>
#include <stdint.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#define chosenHashFunction GCRY_MD_SHA512
typedef unsigned char byte;
using namespace NTL;

uint16_t L, N, outlen_bytes, outlen_bits;
ZZ q, p, g, y, r, s;
std::string signedMessage_str;
std::ifstream readFile;

void readValuesFromFile(const char *, const char *, const char *, std::ifstream &, uint16_t *, uint16_t *, ZZ &, ZZ &, ZZ &, ZZ &, ZZ &, ZZ &);
void readSignedMessage(std::string *, const char *, std::ifstream &);
void validateSign(std::string, const ZZ &, const ZZ &);

int main(int argc, char const *argv[]) {
  if(!gcry_check_version(GCRYPT_VERSION)) {
    fputs ("libgcrypt version mismatch\n", stderr);
    exit(2);
  }
  outlen_bytes = gcry_md_get_algo_dlen(chosenHashFunction);
  outlen_bits = outlen_bytes * 8;

  readValuesFromFile("qpg_values.txt", "SignatoryPublicKey.txt", argv[2], readFile, &L, &N, q, p, g, y, r, s);
  readSignedMessage(&signedMessage_str, argv[1], readFile);
  validateSign(signedMessage_str, r, s);

  return 0;
}

void readValuesFromFile(const char * fileName1, const char * fileName2, const char * fileName3, std::ifstream &in, uint16_t *L, uint16_t *N, ZZ &q, ZZ &p, ZZ&g, ZZ &y, ZZ &r, ZZ &s) {
  std::string tmp_str;
  in.open(fileName1);
  if(!in.is_open()) {
    std::cout << "Couldn't open qpg_values file to read!" << "\n";
    exit(3);
  }
  std::getline(in, tmp_str);
  *L = stoul(tmp_str);
  std::getline(in, tmp_str);
  *N = stoul(tmp_str);
  std::getline(in, tmp_str);
  q = conv<ZZ>(tmp_str.c_str());
  std::getline(in, tmp_str);
  p = conv<ZZ>(tmp_str.c_str());
  std::getline(in, tmp_str);
  g = conv<ZZ>(tmp_str.c_str());
  in.close();
  in.open(fileName2);
  if(!in.is_open()) {
    std::cout << "Couldn't open public key file to read!" << "\n";
    exit(4);
  }
  std::getline(in, tmp_str);
  y = conv<ZZ>(tmp_str.c_str());
  in.close();
  in.open(fileName3);
  if(!in.is_open()) {
    std::cout << "Couldn't open signature file to read!" << "\n";
    exit(5);
  }
  std::getline(in, tmp_str);
  r = conv<ZZ>(tmp_str.c_str());
  std::getline(in, tmp_str);
  s = conv<ZZ>(tmp_str.c_str());
  in.close();
}

void readSignedMessage(std::string *out, const char *msg, std::ifstream &in) {
  in.open(msg);
  if(!in.is_open()) {
    std::cout << "Couldn't open message file to read!" << "\n";
    exit(6);
  }
  std::stringstream sstr;
  sstr << in.rdbuf();
  *out = sstr.str();
  in.close();
}

void validateSign(std::string M, const ZZ &r, const ZZ &s) {
  if(r > q || s > q) {
    std::cout << "the signature is INVALID\n";
    return;
  }
  ZZ w_zz, z_zz, u1_zz, u2_zz, v_zz;
  byte *z_str = (byte *)malloc(sizeof *z_str * outlen_bytes);
  InvMod(w_zz, s, q);
  gcry_md_hash_buffer(chosenHashFunction, z_str, M.c_str(), M.size());
  ZZFromBytes(z_zz, z_str, outlen_bytes);
  if(N < outlen_bits) trunc(z_zz, z_zz, N);
  else trunc(z_zz, z_zz, outlen_bits);
  MulMod(u1_zz, z_zz, w_zz, q);
  MulMod(u2_zz, r, w_zz, q);
  rem(v_zz, MulMod(PowerMod(g, u1_zz, p), PowerMod(y, u2_zz, p), p), q);
  if(v_zz == r) std::cout << "the signature is VALID\n";
  else std::cout << "the signature is INVALID\n";
}
