//
// Created by pengliqiang on 2024/3/12.
//

#include "edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils.h"
#include "../apsi.h"
#include "../serialize.h"
#include "../utils.h"
#include "../polynomials.h"

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_genEncryptionParameters(
        JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray coeff_modulus_bits) {
    uint32_t coeff_size = env->GetArrayLength(coeff_modulus_bits);
    jint* coeff_ptr = env->GetIntArrayElements(coeff_modulus_bits, JNI_FALSE);
    vector<int32_t> bit_sizes(coeff_ptr, coeff_ptr + coeff_size);
    EncryptionParameters parms = EncryptionParameters(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_plain_modulus(plain_modulus);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, std::move(bit_sizes)));
    SEALContext context = SEALContext(parms);
    jbyteArray parms_bytes = serialize_encryption_parms(env, parms);
    return parms_bytes;
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_keyGen(
        JNIEnv *env, jclass, jbyteArray parms_byte) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_byte);
    SEALContext context = SEALContext(parms);
    KeyGenerator key_gen = KeyGenerator(context);
    const SecretKey &secret_key = key_gen.secret_key();
    Serializable<PublicKey> public_key = key_gen.create_public_key();
    Serializable<RelinKeys> relin_keys = key_gen.create_relin_keys();
    jclass list_jcs = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_jcs, "<init>", "()V");
    jobject list_obj = env->NewObject(list_jcs, list_init, "");
    jmethodID list_add = env->GetMethodID(list_jcs, "add", "(Ljava/lang/Object;)Z");
    jbyteArray pk_bytes = serialize_public_key(env, public_key);
    jbyteArray relin_keys_bytes = serialize_relin_keys(env, relin_keys);
    jbyteArray sk_bytes = serialize_secret_key(env, secret_key);
    env->CallBooleanMethod(list_obj, list_add, pk_bytes);
    env->CallBooleanMethod(list_obj, list_add, sk_bytes);
    env->CallBooleanMethod(list_obj, list_add, relin_keys_bytes);
    return list_obj;
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_preprocessDatabase(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray database_coeffs, jint ps_low_power) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context(parms);
    Evaluator evaluator(context);
    if (ps_low_power > 0) {
        auto low_powers_parms_id = get_parms_id_for_chain_idx(context, 2);
        vector<Plaintext> plaintexts = deserialize_plaintexts(env, database_coeffs, context);
        uint32_t ps_high_degree = ps_low_power + 1;
        for (uint32_t i = 0; i < plaintexts.size(); i++) {
            if ((i % ps_high_degree) != 0) {
                evaluator.transform_to_ntt_inplace(plaintexts[i], low_powers_parms_id);
            }
        }
        return serialize_plaintexts(env, plaintexts);
    } else {
        auto parms_id = get_parms_id_for_chain_idx(context, 1);
        vector<Plaintext> plaintexts = deserialize_plaintexts(env, database_coeffs, context);
        for (uint32_t i = 1; i < plaintexts.size(); i++) {
            evaluator.transform_to_ntt_inplace(plaintexts[i], parms_id);
        }
        return serialize_plaintexts(env, plaintexts);
    }
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_generateQuery(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jobjectArray coeffs_array) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = SEALContext(parms);
    SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
    vector<Plaintext> plain_query = deserialize_plaintexts_from_coeff(env, coeffs_array, context);
    Encryptor encryptor(context, secret_key);
    vector<Serializable<Ciphertext>> query;
    for (auto & plaintext : plain_query) {
        query.push_back(encryptor.encrypt_symmetric(plaintext));
    }
    return serialize_ciphertexts(env, query);
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_computeEncryptedPowers(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray relin_keys_bytes, jobject query_list,
        jobjectArray jparent_powers, jintArray jsource_power_index, jint ps_low_power) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = SEALContext(parms);
    RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
    Evaluator evaluator(context);
    vector<Ciphertext> query = deserialize_ciphertexts(env, query_list, context);
    // compute all the powers of the receiver's input.
    jint* index_ptr = env->GetIntArrayElements(jsource_power_index, JNI_FALSE);
    vector<uint32_t> source_power_index;
    source_power_index.reserve(env->GetArrayLength(jsource_power_index));
    for (uint32_t i = 0; i < env->GetArrayLength(jsource_power_index); i++) {
        source_power_index.push_back(index_ptr[i]);
    }
    uint32_t target_power_size = env->GetArrayLength(jparent_powers);
    vector<vector<uint32_t>> parent_powers(target_power_size);
    for (uint32_t i = 0; i < target_power_size; i++) {
        parent_powers[i].reserve(2);
        auto rows = (jintArray) env->GetObjectArrayElement(jparent_powers, (jint) i);
        jint* cols = env->GetIntArrayElements(rows, JNI_FALSE);
        parent_powers[i].push_back(cols[0]);
        parent_powers[i].push_back(cols[1]);
    }
    vector<Ciphertext> encrypted_powers = compute_encrypted_powers(parms, query, parent_powers, source_power_index, ps_low_power, relin_keys);
    return serialize_ciphertexts(env, encrypted_powers);
}

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_optComputeMatches(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray relin_keys_bytes, jobject database_coeffs,
        jobject query_list, jint ps_low_power, jlongArray r_coeffs) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context(parms);
    RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
    Evaluator evaluator(context);
    // encrypted query powers
    vector<Ciphertext> query_powers = deserialize_ciphertexts(env, query_list, context);
    vector<Plaintext> plaintexts = deserialize_plaintexts(env, database_coeffs, context);
    Ciphertext f_evaluated = polynomial_evaluation(parms, query_powers, plaintexts, ps_low_power, relin_keys);
    Plaintext r = deserialize_plaintext_from_coeff(env, r_coeffs, context);
    evaluator.add_plain_inplace(f_evaluated, r);
    while (f_evaluated.parms_id() != context.last_parms_id()) {
        evaluator.mod_switch_to_next_inplace(f_evaluated);
    }
    return serialize_ciphertext(env, f_evaluated);
}

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_naiveComputeMatches(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray database_coeffs, jobject query_list, jlongArray r_coeffs) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context(parms);
    Evaluator evaluator(context);
    // encrypted query powers
    vector<Ciphertext> query_powers = deserialize_ciphertexts(env, query_list, context);
    vector<Plaintext> plaintexts = deserialize_plaintexts(env, database_coeffs, context);
    Ciphertext f_evaluated = polynomial_evaluation(parms, query_powers, plaintexts);
    Plaintext r = deserialize_plaintext_from_coeff(env, r_coeffs, context);
    evaluator.add_plain_inplace(f_evaluated, r);
    while (f_evaluated.parms_id() != context.last_parms_id()) {
        evaluator.mod_switch_to_next_inplace(f_evaluated);
    }
    return serialize_ciphertext(env, f_evaluated);
}

[[maybe_unused]] JNIEXPORT
jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_upso_upsu_tcl23_Tcl23UpsuNativeUtils_decodeReply(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_byte) {
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = SEALContext(parms);
    SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
    BatchEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    uint32_t slot_count = encoder.slot_count();
    Ciphertext response = deserialize_ciphertext(env, response_byte, context);
    int32_t noise_budget = decryptor.invariant_noise_budget(response);
    jclass exception = env->FindClass("java/lang/Exception");
    if (noise_budget == 0) {
        env->ThrowNew(exception, "noise budget is 0.");
        return nullptr;
    }
    Plaintext decrypted;
    vector<uint64_t> dec_vec(slot_count);
    decryptor.decrypt(response, decrypted);
    encoder.decode(decrypted, dec_vec);
    jlongArray coeffs = env->NewLongArray((jsize) dec_vec.size());
    jlong fill[dec_vec.size()];
    for (uint32_t i = 0; i < dec_vec.size(); i++) {
        fill[i] = (jlong) dec_vec[i];
    }
    env->SetLongArrayRegion(coeffs, 0, (jsize) dec_vec.size(), fill);
    return coeffs;
}