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
ZZ q, p, g, x, k, k_inv, r, z, s;
std::string messageToSign_str;
std::ifstream readFile;
std::ofstream writeFile;

void readValuesFromFile(const char *, const char *, std::ifstream &, uint16_t *, uint16_t *, ZZ &, ZZ &, ZZ &, ZZ &);
void gen_k_inverse_k_r(ZZ &, ZZ &, ZZ &);
void readMessageToSign(std::string *, const char *, std::ifstream &);
void signMessage(std::string, const char *, std::ofstream &);

int main(int argc, char const *argv[]) {
  if(!gcry_check_version(GCRYPT_VERSION)) {
    fputs ("libgcrypt version mismatch\n", stderr);
    exit(2);
  }
  outlen_bytes = gcry_md_get_algo_dlen(chosenHashFunction);
  outlen_bits = outlen_bytes * 8;

  readValuesFromFile("qpg_values.txt", "SignatoryPrivateKey.txt", readFile, &L, &N, q, p, g, x);
  //std::cout << "L = " << L << "\n" << "N = " << N << "\n" << "q = " << q  << "\n" << "p = " << p << "\n" << "g = " << g << "\n" << "x = " << x << "\n";
  gen_k_inverse_k_r(k, k_inv, r);
  readMessageToSign(&messageToSign_str, argv[1], readFile);
  signMessage(messageToSign_str, "signature.txt", writeFile);

  return 0;
}

void readValuesFromFile(const char * fileName1, const char * fileName2, std::ifstream &in, uint16_t *L, uint16_t *N, ZZ &q, ZZ &p, ZZ&g, ZZ &x) {
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
    std::cout << "Couldn't open private key file to read!" << "\n";
    exit(4);
  }
  std::getline(in, tmp_str);
  x = conv<ZZ>(tmp_str.c_str());
  in.close();
}

void gen_k_inverse_k_r(ZZ &k, ZZ &k_inv, ZZ &r) {
  ZZ c;
  RandomLen(c, N + 64);
  rem(k, c, q - 1);
  k++;
  InvMod(k_inv, k, q);
  rem(r, PowerMod(g, k, p), q);
}

void readMessageToSign(std::string *out, const char *msg, std::ifstream &in) {
  in.open(msg);
  if(!in.is_open()) {
    std::cout << "Couldn't open message file to read!" << "\n";
    exit(5);
  }
  std::stringstream sstr;
  sstr << in.rdbuf();
  *out = sstr.str();
  in.close();
}

void signMessage(std::string M, const char *fileName, std::ofstream &out) {
  ZZ z_zz, s;
  byte *z_str = (byte *)malloc(sizeof *z_str * outlen_bytes);
  gcry_md_hash_buffer(chosenHashFunction, z_str, M.c_str(), M.size());
  ZZFromBytes(z_zz, z_str, outlen_bytes);
  if(N < outlen_bits) trunc(z_zz, z_zz, N);
  else trunc(z_zz, z_zz, outlen_bits);
  rem(s, k_inv * (z_zz + (x * r)), q);

  out.open(fileName);
  if(!out.is_open()) {
    std::cout << "Couldn't open signature file to write!" << "\n";
    exit(6);
  }
  out << r << "\n" << s << "\n";
  out.close();
}
