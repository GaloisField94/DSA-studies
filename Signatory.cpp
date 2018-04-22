#include <NTL/ZZ.h>
#include <gcrypt.h>
#include <stdint.h>
#include <fstream>
#include <sstream>
#include <string.h>
#define chosenHashFunction GCRY_MD_SHA512
typedef unsigned char byte;
using namespace NTL;

uint16_t parameters[4][3] = {{1024, 160, 40},
                             {2048, 224, 56},
                             {2048, 256, 56},
                             {3072, 256, 64}};

uint16_t L, N, MR_iterations, seedlen_bits, seedlen_bytes, outlen_bits, outlen_bytes, n, b, counter;
ZZ p, q, g, domainParameterSeed_zz, x, y, k, k_inv, U_zz, offset, tmp_zz;
byte *U_str, *domainParameterSeed_str, *tmp_str;
std::string messageToSign_str;
std::ifstream readMessageFile;
std::ofstream writeGeneratedValues;
bool flag_q, flag_p;

std::string readMessageToSign(std::ifstream &);
void gen_q_and_p(ZZ &, ZZ &, ZZ &, uint16_t *);
void gen_g(ZZ &);
void gen_x_y(ZZ &, ZZ &);
void gen_k_and_inverse_k(ZZ &, ZZ &);

int main(int argc, char const *argv[]) {
  if(!gcry_check_version(GCRYPT_VERSION)) {
    fputs ("libgcrypt version mismatch\n", stderr);
    exit(2);
  }

  //initializing variables
  SetSeed(RandomBnd(conv<ZZ>("9409250011798120900227")));
  L = parameters[atoi(argv[1])][0];
  N = parameters[atoi(argv[1])][1];
  MR_iterations = parameters[atoi(argv[1])][2];
  seedlen_bits = N;
  seedlen_bytes = seedlen_bits/8;
  outlen_bytes = gcry_md_get_algo_dlen(chosenHashFunction);
  outlen_bits = outlen_bytes*8;
  n = ceil(L/(outlen_bits))-1;
  b = L-1-(n*(outlen_bits));
  U_str = (byte *)malloc(sizeof *U_str * outlen_bytes);
  domainParameterSeed_str = (byte *)malloc(sizeof *U_str * seedlen_bytes);
  tmp_str = (byte *)malloc(sizeof *tmp_str * outlen_bytes);
  flag_q = false;
  flag_p = false;
  // std::cout << "L = " << L << "\n";
  // std::cout << "N = " << N << "\n";
  // std::cout << "MR_iterations = " << MR_iterations << "\n";
  // std::cout << "seedlen_bits = " << seedlen_bits << "\n";
  // std::cout << "seedlen_bytes = " << seedlen_bytes << "\n";
  // std::cout << "outlen_bits = " << outlen_bits << "\n";
  // std::cout << "outlen_bytes = " << outlen_bytes << "\n";
  // std::cout << "n = " << n << "\n";
  // std::cout << "b = " << b << "\n";

  //reading message to string
  readMessageFile.open("message.txt");
  if(!readMessageFile.is_open()) {
    std::cout << "Couldn't open message file to read!" << "\n";
    return 0;
  }
  messageToSign_str = readMessageToSign(readMessageFile);
  readMessageFile.close();
  //std::cout << messageToSign_str;

  //obtaining q and p
  gen_q_and_p(q, p, domainParameterSeed_zz, &counter);
  //std::cout << "q = " << q << "\n" << "is q prime? " << flag_q << "\n" << "q is a " << NumBits(q) << "-bit number" << "\n";
  //std::cout << "p = " << p << "\n" << "is p prime? " << flag_p << "\n" << "p is a " << NumBits(p) << "-bit number" << "\n";
  gen_g(g);
  //std::cout << "g = " << g << "\n";
  gen_x_y(x, y);
  //std::cout << "x = " << x << "\n" << "y = " << y << "\n";
  gen_k_and_inverse_k(k, k_inv);
  std::cout << "k = " << k << "\n" << "k_inv = " << k_inv << "\n";

  writeGeneratedValues.open("generated_values.txt");
  if(!writeGeneratedValues.is_open()) {
    std::cout << "Couldn't open values file to write!" << "\n";
    return 0;
  }
  writeGeneratedValues << q << "\n" << p << "\n" << g << "\n" << domainParameterSeed_zz << "\n" << counter << "\n" << y << "\n";

  return 0;
}

std::string readMessageToSign(std::ifstream& in) {
    std::stringstream sstr;
    sstr << in.rdbuf();
    return sstr.str();
}

void gen_q_and_p(ZZ &q, ZZ &p, ZZ &domainParameterSeed_zz, uint16_t *counter) {
  do {
    //obtaining q
    do {
      RandomLen(domainParameterSeed_zz, seedlen_bits);
      BytesFromZZ(domainParameterSeed_str, domainParameterSeed_zz, seedlen_bytes);
      gcry_md_hash_buffer(chosenHashFunction, U_str, domainParameterSeed_str, seedlen_bytes);
      ZZFromBytes(U_zz, U_str, outlen_bytes);
      if(seedlen_bits < outlen_bits) trunc(U_zz, U_zz, seedlen_bits);
      q = power(ZZ(2), N - 1) + U_zz + 1 - rem(U_zz, 2);
      if(NumBits(q) != N) continue;
      flag_q = ProbPrime(q, MR_iterations);
    } while(!flag_q);

    //obtaining p
    ZZ V_zz[n + 1], W = ZZ(0), X = ZZ(0), c = ZZ(0);
    byte **V_str = (byte **)malloc(sizeof *V_str * (n + 1));
    for(uint16_t i = 0; i <= n; i++) V_str[i] = (byte *)malloc(sizeof *V_str[i] * outlen_bytes);

    offset = 1;
    for(*counter = 0; *counter < 4 * L; (*counter)++) {
      for(uint16_t j = 0; j <= n; j++) {
        rem(tmp_zz, domainParameterSeed_zz + offset + j, power2_ZZ(seedlen_bits));
        BytesFromZZ(tmp_str, tmp_zz, seedlen_bytes);
        gcry_md_hash_buffer(chosenHashFunction, V_str[j], tmp_str, seedlen_bytes);
        ZZFromBytes(V_zz[j], V_str[j], outlen_bytes);
      }
      for(uint16_t j = 0; j <= n; j++) add(W, W, MulMod(V_zz[j], power2_ZZ(j * outlen_bits), power2_ZZ(b)));
      add(X, W, power2_ZZ(L-1));
      rem(c, X, 2 * q);
      sub(p, X, c - 1);
      if(NumBits(p) != L) {
        offset += n + 1;
        continue;
      }
      flag_p = ProbPrime(p, MR_iterations);
      if(flag_p) break;
      offset += n + 1;
    }
  } while(!flag_p);
}

void gen_g(ZZ &g) {
  uint16_t count = 0;
  uint32_t index = RandomBnd(256) << 16;
  uint64_t ggen = 0x6767656E000000;
  ZZ e, W_zz;
  byte *W_str = (byte *)malloc(sizeof *W_str * outlen_bytes);
  byte *U_str_local = (byte *)malloc(sizeof *U_str_local * (seedlen_bytes + 7));

  div(e, p - 1, q);
  for(;;) {
    count++;
    if(count == 0) {
      std::cout << "Couldn't generate g :<" << "\n";
      exit(3);
    }
    LeftShift(tmp_zz, domainParameterSeed_zz, 56);
    U_zz = tmp_zz + ggen + index + count;
    BytesFromZZ(U_str_local, U_zz, seedlen_bytes + 7);
    gcry_md_hash_buffer(chosenHashFunction, W_str, U_str_local, seedlen_bytes + 7);
    ZZFromBytes(W_zz, W_str, seedlen_bytes + 7);
    PowerMod(g, W_zz, e, p);
    if(g > 1) break;
  }
}

void gen_x_y(ZZ &x, ZZ &y) {
  ZZ c;
  RandomLen(c, N + 64);
  rem(x, c, q - 1);
  x++;
  PowerMod(y, g, x, p);
}

void gen_k_and_inverse_k(ZZ &k, ZZ &k_inv) {
  ZZ c;
  RandomLen(c, N + 64);
  rem(k, c, q - 1);
  k++;
  InvMod(k_inv, k, q);
}
