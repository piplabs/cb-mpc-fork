/**
 * TypeScript loader for the cb-mpc TDH2 WASM module.
 *
 * Usage:
 *   import { initTdh2Wasm } from "./loader.js";
 *   const tdh2 = await initTdh2Wasm();
 *   const ct = tdh2.encrypt(pubKeyPoint, plaintext, label);
 *   const pt = tdh2.combine({ ... });
 *
 * Copy this file to your TypeScript SDK (e.g. packages/crypto/src/wasm/loader.ts)
 * alongside the built cb-mpc-tdh2.js and cb-mpc-tdh2.wasm files.
 */

// The Emscripten-generated module factory
// Adjust this import path to match your project layout
import createCbMpcModule from "./dist/cb-mpc-tdh2.js";

/** Opaque WASM module instance */
interface EmscriptenModule {
  _malloc(size: number): number;
  _free(ptr: number): void;
  _wasm_tdh2_pub_key_from_point(data: number, size: number, outHandle: number): number;
  _wasm_tdh2_free_pub_key(handle: number): void;
  _wasm_tdh2_encrypt(
    handle: number,
    plainPtr: number, plainSize: number,
    labelPtr: number, labelSize: number,
    outPtrPtr: number, outSizePtr: number,
  ): number;
  _wasm_tdh2_verify(
    handle: number,
    ctPtr: number, ctSize: number,
    labelPtr: number, labelSize: number,
  ): number;
  _wasm_ac_new_node(nodeType: number, namePtr: number, nameSize: number, threshold: number): number;
  _wasm_ac_add_child(parent: number, child: number): void;
  _wasm_ac_set_node_pid(node: number, pid: number): void;
  _wasm_ac_new(root: number, curveCode: number): number;
  _wasm_ac_free(handle: number): void;
  _wasm_tdh2_combine(
    acHandle: number, pubKeyHandle: number, n: number,
    namesData: number, namesSizes: number,
    pubSharesData: number, pubSharesSizes: number,
    ctData: number, ctSize: number,
    labelData: number, labelSize: number,
    partialsData: number, partialsSizes: number,
    outPtrPtr: number, outSizePtr: number,
  ): number;
  _wasm_ptr_size(): number;
  HEAPU8: Uint8Array;
  HEAP32: Int32Array;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
}

/** TDH2 ciphertext (serialized) */
export interface TDH2Ciphertext {
  raw: Uint8Array;
  label: Uint8Array;
}

/** A single partial decryption from a validator */
export interface PartialDecryption {
  /** Validator name (used as key in the access structure) */
  name: string;
  /** Serialized public share point */
  pubShare: Uint8Array;
  /** Serialized partial decryption */
  partial: Uint8Array;
}

/** Ed25519 curve code in cb-mpc (NID_ED25519 = 0x043f = 1087) */
export const CURVE_ED25519 = 1087;

/** Secp256k1 curve code (NID_secp256k1 = 714) */
export const CURVE_SECP256K1 = 714;

/** P-256 curve code (NID_X9_62_prime256v1 = 415) */
export const CURVE_P256 = 415;

class TDH2Wasm {
  private M: EmscriptenModule;

  constructor(module: EmscriptenModule) {
    this.M = module;
  }

  /**
   * Encrypt plaintext to a TDH2 public key.
   *
   * @param pubKeyPoint  Serialized EC point (curve-code prefixed) — the DKG global public key
   * @param plaintext    Data to encrypt
   * @param label        Associated data label
   * @returns Serialized TDH2 ciphertext
   */
  encrypt(pubKeyPoint: Uint8Array, plaintext: Uint8Array, label: Uint8Array): TDH2Ciphertext {
    const M = this.M;

    // Create public key from point
    const pointPtr = this.allocBytes(pubKeyPoint);
    const handlePtr = M._malloc(4);
    try {
      let rv = M._wasm_tdh2_pub_key_from_point(pointPtr, pubKeyPoint.length, handlePtr);
      if (rv !== 0) throw new Error(`wasm_tdh2_pub_key_from_point failed: ${rv}`);
      const pkHandle = M.getValue(handlePtr, "i32");

      // Encrypt
      const plainPtr = this.allocBytes(plaintext);
      const labelPtr = this.allocBytes(label);
      const outPtrPtr = M._malloc(4);
      const outSizePtr = M._malloc(4);
      try {
        rv = M._wasm_tdh2_encrypt(
          pkHandle,
          plainPtr, plaintext.length,
          labelPtr, label.length,
          outPtrPtr, outSizePtr,
        );
        if (rv !== 0) throw new Error(`wasm_tdh2_encrypt failed: ${rv}`);

        const raw = this.readResult(outPtrPtr, outSizePtr);
        return { raw, label: new Uint8Array(label) };
      } finally {
        M._free(plainPtr);
        M._free(labelPtr);
        M._free(outPtrPtr);
        M._free(outSizePtr);
        M._wasm_tdh2_free_pub_key(pkHandle);
      }
    } finally {
      M._free(pointPtr);
      M._free(handlePtr);
    }
  }

  /**
   * Verify a TDH2 ciphertext is well-formed.
   *
   * @returns true if valid
   */
  verify(pubKeyPoint: Uint8Array, ciphertext: Uint8Array, label: Uint8Array): boolean {
    const M = this.M;
    const pointPtr = this.allocBytes(pubKeyPoint);
    const handlePtr = M._malloc(4);
    try {
      let rv = M._wasm_tdh2_pub_key_from_point(pointPtr, pubKeyPoint.length, handlePtr);
      if (rv !== 0) return false;
      const pkHandle = M.getValue(handlePtr, "i32");

      const ctPtr = this.allocBytes(ciphertext);
      const labelPtr = this.allocBytes(label);
      try {
        rv = M._wasm_tdh2_verify(pkHandle, ctPtr, ciphertext.length, labelPtr, label.length);
        return rv === 0;
      } finally {
        M._free(ctPtr);
        M._free(labelPtr);
        M._wasm_tdh2_free_pub_key(pkHandle);
      }
    } finally {
      M._free(pointPtr);
      M._free(handlePtr);
    }
  }

  /**
   * Combine partial decryptions to recover plaintext.
   *
   * @param pubKeyPoint  Serialized DKG global public key point
   * @param ciphertext   TDH2 ciphertext (from encrypt)
   * @param label        Label used during encryption
   * @param partials     Array of partial decryptions from validators
   * @param threshold    Threshold value for the access structure
   * @param curveCode    Curve code (default: CURVE_ED25519)
   * @returns Recovered plaintext
   */
  combine(params: {
    pubKeyPoint: Uint8Array;
    ciphertext: Uint8Array;
    label: Uint8Array;
    partials: PartialDecryption[];
    threshold: number;
    curveCode?: number;
  }): Uint8Array {
    const { pubKeyPoint, ciphertext, label, partials, threshold, curveCode = CURVE_ED25519 } = params;
    const M = this.M;
    const n = partials.length;

    // 1. Create public key
    const pointPtr = this.allocBytes(pubKeyPoint);
    const handlePtr = M._malloc(4);
    let rv = M._wasm_tdh2_pub_key_from_point(pointPtr, pubKeyPoint.length, handlePtr);
    if (rv !== 0) {
      M._free(pointPtr);
      M._free(handlePtr);
      throw new Error(`wasm_tdh2_pub_key_from_point failed: ${rv}`);
    }
    const pkHandle = M.getValue(handlePtr, "i32");
    M._free(pointPtr);
    M._free(handlePtr);

    // 2. Build access structure: threshold gate with n leaf children
    const encoder = new TextEncoder();
    const rootHandle = M._wasm_ac_new_node(
      1, // threshold gate
      this.allocStringTemp("root"),
      4, // "root".length
      threshold,
    );

    const leafHandles: number[] = [];
    for (const p of partials) {
      const nameBytes = encoder.encode(p.name);
      const namePtr = this.allocBytes(nameBytes);
      const leafHandle = M._wasm_ac_new_node(0, namePtr, nameBytes.length, 0);
      M._free(namePtr);
      leafHandles.push(leafHandle);
      M._wasm_ac_add_child(rootHandle, leafHandle);
    }

    const acHandle = M._wasm_ac_new(rootHandle, curveCode);

    // 3. Build concatenated arrays for names, pub_shares, partials
    const namesBufs = partials.map((p) => encoder.encode(p.name));
    const { dataPtr: namesDataPtr, sizesPtr: namesSizesPtr } = this.allocConcatArrays(namesBufs);
    const { dataPtr: pubSharesDataPtr, sizesPtr: pubSharesSizesPtr } = this.allocConcatArrays(
      partials.map((p) => p.pubShare),
    );
    const { dataPtr: partialsDataPtr, sizesPtr: partialsSizesPtr } = this.allocConcatArrays(
      partials.map((p) => p.partial),
    );

    // 4. Allocate ciphertext and label
    const ctPtr = this.allocBytes(ciphertext);
    const labelPtr = this.allocBytes(label);
    const outPtrPtr = M._malloc(4);
    const outSizePtr = M._malloc(4);

    try {
      rv = M._wasm_tdh2_combine(
        acHandle, pkHandle, n,
        namesDataPtr, namesSizesPtr,
        pubSharesDataPtr, pubSharesSizesPtr,
        ctPtr, ciphertext.length,
        labelPtr, label.length,
        partialsDataPtr, partialsSizesPtr,
        outPtrPtr, outSizePtr,
      );
      if (rv !== 0) throw new Error(`wasm_tdh2_combine failed: ${rv}`);

      return this.readResult(outPtrPtr, outSizePtr);
    } finally {
      M._free(namesDataPtr);
      M._free(namesSizesPtr);
      M._free(pubSharesDataPtr);
      M._free(pubSharesSizesPtr);
      M._free(partialsDataPtr);
      M._free(partialsSizesPtr);
      M._free(ctPtr);
      M._free(labelPtr);
      M._free(outPtrPtr);
      M._free(outSizePtr);
      M._wasm_ac_free(acHandle);
      M._wasm_tdh2_free_pub_key(pkHandle);
    }
  }

  // ============ Helpers =============

  /** Allocate and copy bytes into WASM heap. Caller must free. */
  private allocBytes(data: Uint8Array): number {
    const ptr = this.M._malloc(data.length);
    this.M.HEAPU8.set(data, ptr);
    return ptr;
  }

  /** Allocate a temporary string in WASM heap. Caller must free. */
  private allocStringTemp(s: string): number {
    const bytes = new TextEncoder().encode(s);
    return this.allocBytes(bytes);
  }

  /**
   * Concatenate multiple Uint8Arrays into a single WASM buffer + sizes array.
   * Returns { dataPtr, sizesPtr } — both must be freed by caller.
   */
  private allocConcatArrays(arrays: Uint8Array[]): { dataPtr: number; sizesPtr: number } {
    const totalSize = arrays.reduce((sum, a) => sum + a.length, 0);
    const dataPtr = this.M._malloc(totalSize);
    const sizesPtr = this.M._malloc(arrays.length * 4); // int32 per entry

    let offset = 0;
    for (let i = 0; i < arrays.length; i++) {
      this.M.HEAPU8.set(arrays[i], dataPtr + offset);
      this.M.HEAP32[(sizesPtr >> 2) + i] = arrays[i].length;
      offset += arrays[i].length;
    }

    return { dataPtr, sizesPtr };
  }

  /** Read a (ptr*, size*) result pair from WASM, copy data out, and free the WASM buffer. */
  private readResult(outPtrPtr: number, outSizePtr: number): Uint8Array {
    const dataPtr = this.M.getValue(outPtrPtr, "i32");
    const dataSize = this.M.getValue(outSizePtr, "i32");
    const result = new Uint8Array(dataSize);
    result.set(this.M.HEAPU8.subarray(dataPtr, dataPtr + dataSize));
    this.M._free(dataPtr);
    return result;
  }
}

let instance: TDH2Wasm | null = null;

/**
 * Initialize the WASM module. Must be called once before using encrypt/combine.
 * Subsequent calls return the cached instance.
 */
export async function initTdh2Wasm(): Promise<TDH2Wasm> {
  if (instance) return instance;

  const Module = await createCbMpcModule() as unknown as EmscriptenModule;

  // Sanity check
  const ptrSize = Module._wasm_ptr_size();
  if (ptrSize !== 4) {
    console.warn(`Unexpected WASM pointer size: ${ptrSize} (expected 4)`);
  }

  instance = new TDH2Wasm(Module);
  return instance;
}

/**
 * Reset the WASM instance (for testing).
 */
export function resetTdh2Wasm(): void {
  instance = null;
}

export { TDH2Wasm };
