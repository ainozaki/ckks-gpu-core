/* Copyright (c) by CryptoLab Inc. and Seoul National University R&DB Foundation.
 * This library is licensed under a
 * Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
 * You should have received a copy of the license along with this
 * work. If not, see <http://creativecommons.org/licenses/by-nc-sa/4.0/>.
 */


#include <complex>
#include <random>

#include "gtest/gtest.h"
#include "public/Ciphertext.h"
#include "public/Context.h"
#include "public/Define.h"
#include "public/EvaluationKey.h"
#include "public/MultPtxtBatch.h"
#include "public/Parameter.h"
#include "public/Test.h"

class E2ETest : public ckks::Test,
                   public ::testing::TestWithParam<ckks::Parameter> {
 protected:
  E2ETest() : ckks::Test(GetParam()){};

  void COMPARE(const ckks::DeviceVector& ref,
               const ckks::DeviceVector& out) const {
    ASSERT_EQ(ckks::HostVector(ref), ckks::HostVector(out));
  }

  void COMPARE(const ckks::HostVector& ref, const ckks::HostVector& out) const {
    ASSERT_EQ(ref, out);
  }

  void COMPARE_APPROXIMATE(std::complex<double> *ref,
                           std::complex<double> *out, int size) const {
    for (size_t i = 0; i < size; i++) {
      ASSERT_NEAR(ref[i].real(), out[i].real(), 1e-2);
      ASSERT_NEAR(ref[i].imag(), out[i].imag(), 1e-2);
    }
  }

  void COMPARE(const uint64_t *ref, const uint64_t *out, int size) const {
    for (size_t i = 0; i < size; i++) {
      ASSERT_EQ(ref[i], out[i]);
    }
  }

  template <typename T>
  void print_vector(std::vector<T> vec, std::size_t print_size = 4){
    std::size_t slot_count = vec.size();
    for (std::size_t i = 0; i < std::min(slot_count, print_size); i++) {
      std::cout << vec[i] << " ";
    }
    std::cout << std::endl;
  }
};

TEST_P(E2ETest, Encode) {
  int slots = 8;
  std::complex<double> *mvec = new std::complex<double>[slots];
  std::complex<double> *mvec_ref = new std::complex<double>[slots];
  std::complex<double> *mvec_decoded = new std::complex<double>[slots];
  uint64_t *mvec_encoded = new uint64_t[param.chain_length_ << param.log_degree_];


  for (int i = 0; i < slots; i++) {
    mvec[i] = std::complex<double>(i, i);
    mvec_ref[i] = std::complex<double>(i, i);
  }

  context.Encode(mvec_encoded, mvec, slots);
  context.Decode(mvec_decoded, mvec_encoded, slots);

  COMPARE_APPROXIMATE(mvec_ref, mvec_decoded, slots);
}

TEST_P(E2ETest, Encrypt){
  int slots = 8;
  std::complex<double> *mvec = new std::complex<double>[slots];
  std::complex<double> *mvec_ref = new std::complex<double>[slots];
  
  for (int i = 0; i < slots; i++) {
    mvec[i] = std::complex<double>(i, i);
    mvec_ref[i] = std::complex<double>(i, i);
  }

  // encrypt and encode
  context.AddSecretkey();
  context.AddEncryptionKey();
  ckks::Ciphertext ct0 = context.Encrypt(mvec, slots);
  
  // some operations

  // decrypt and decode
  std::complex<double> *mvec_decoded = context.Decrypt(ct0, slots);

  COMPARE_APPROXIMATE(mvec_ref, mvec_decoded, slots);
}

TEST_P(E2ETest, NTTHost){
  int n = param.chain_length_ << param.log_degree_;
  ckks::HostVector a(n);
  ckks::HostVector a_ref(n);
  for (int i = 0; i < param.chain_length_; i++){
    for (int j = 0; j < param.degree_; j++){
      a[i * param.degree_ + j] = j;
      a_ref[i * param.degree_ + j] = j;
    }
  }
  context.ToNTTHost(a, param.chain_length_);
  context.FromNTTHost(a, param.chain_length_);

  COMPARE(a, a_ref);
}

TEST_P(E2ETest, Add){
  int slots = 8;
  std::complex<double> *mvec_a = new std::complex<double>[slots];
  std::complex<double> *mvec_b = new std::complex<double>[slots];
  std::complex<double> *mvec_ref = new std::complex<double>[slots];
  
  for (int i = 0; i < slots; i++) {
    mvec_a[i] = std::complex<double>(i, i);
    mvec_b[i] = std::complex<double>(i, i);
    mvec_ref[i] = mvec_a[i] + mvec_b[i];
  }

  // encrypt and encode
  context.AddSecretkey();
  context.AddEncryptionKey();
  ckks::Ciphertext ct0 = context.Encrypt(mvec_a, slots);
  ckks::Ciphertext ct1 = context.Encrypt(mvec_b, slots);
  
  // some operations
  ckks::Ciphertext ct2;
  context.Add(ct0, ct1, ct2);

  // decrypt and decode
  std::complex<double> *mvec_decoded = context.Decrypt(ct2, slots);

  COMPARE_APPROXIMATE(mvec_ref, mvec_decoded, slots);
}

TEST_P(E2ETest, Mult){
  int slots = 8;
  std::complex<double> *mvec_a = new std::complex<double>[slots];
  std::complex<double> *mvec_b = new std::complex<double>[slots];
  std::complex<double> *mvec_ref = new std::complex<double>[slots];
  
  for (int i = 0; i < slots; i++) {
    mvec_a[i] = std::complex<double>(i, i);
    mvec_b[i] = std::complex<double>(i, i);
    mvec_ref[i] = mvec_a[i] * mvec_b[i];
  }

  // encrypt and encode
  context.AddSecretkey();
  context.AddEncryptionKey();
  ckks::Ciphertext ctx = context.Encrypt(mvec_a, slots);
  ckks::Ciphertext cty = context.Encrypt(mvec_b, slots);
  
  // HMult operations
  ckks::Ciphertext ctout;
  ckks::DeviceVector axax, bxbx, axbx1, axbx2, sum_ax, sum_bx;
  
  // Mult
  context.HadamardMult(ctx.getAxDevice(), cty.getAxDevice(), axax);
  context.HadamardMult(ctx.getBxDevice(), cty.getBxDevice(), bxbx);
  context.Add(ctx.getAxDevice(), ctx.getBxDevice(), axbx1);
  context.Add(cty.getAxDevice(), cty.getBxDevice(), axbx2);
  context.HadamardMult(axbx1, axbx2, axbx1);

  // iNTT + ModUp
  ckks::DeviceVector modup = context.ModUp(axax);

  // NTT
  context.ToNTTInplace(modup.data(), 0, param.chain_length_ + param.num_special_moduli_);

  // KeySwitch
  // TODO: key
  auto key = GetRandomKey();
  context.KeySwitch(modup, key, sum_ax, sum_bx);

  // iNTT + ModDown
  context.ModDown(sum_ax, sum_ax, param.chain_length_);
  context.ModDown(sum_bx, sum_bx, param.chain_length_);

  // NTT
  context.ToNTTInplace(sum_ax.data(), 0, sum_ax.size() / param.degree_);
  context.ToNTTInplace(sum_bx.data(), 0, sum_bx.size() / param.degree_);

  // sum
  context.Add(sum_ax, axbx1, sum_ax);
  context.Add(sum_ax, bxbx, sum_ax);
  context.Add(sum_ax, axax, ctout.getAxDevice());
  context.Add(sum_bx, bxbx, ctout.getBxDevice());

  // decrypt and decode
  std::complex<double> *mvec_decoded = context.Decrypt(ctout, slots);

  COMPARE_APPROXIMATE(mvec_ref, mvec_decoded, slots);
}

INSTANTIATE_TEST_SUITE_P(Params, E2ETest,
                         ::testing::Values(PARAM_LARGE_DNUM, PARAM_SMALL_DNUM));