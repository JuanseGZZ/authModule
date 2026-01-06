// van a aestar todas las class del proyecto

// protocol/Packet.js

import { b64uEncode, b64uDecode } from "../crypto/Base64Url.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/AESGCM.js";
import { encryptFiles, decryptFiles } from "../protocol/FilesCipherHandler.js";

export class Packet {
  constructor({
    refresh_token = "",
    access_token = "",
    data = {},
    aes_key,
    user_id,
    files = [],
  }) {
    if (typeof aes_key !== "string" || !aes_key) {
      throw new Error("Packet: aes_key invalida");
    }
    if (typeof user_id !== "string") {
      throw new Error("Packet: user_id invalido");
    }

    this.refresh_token = refresh_token;
    this.access_token = access_token;
    this.data = data;
    this.aes_key = aes_key;
    this.user_id = user_id;
    this.files = files || [];
  }

  // ===============================
  // helpers internos
  // ===============================

  static normalizeAesKey(aesKeyStr) {
    const enc = new TextEncoder();
    let bytes = enc.encode(aesKeyStr);

    if (bytes.length > 32) {
      bytes = bytes.slice(0, 32);
    }

    if (bytes.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(bytes);
      padded.fill(0x30, bytes.length); // '0'
      bytes = padded;
    }

    return bytes; // Uint8Array(32)
  }

  // ===============================
  // ENCRYPT
  // ===============================
  async encryptAES() {
    const keyBytes = Packet.normalizeAesKey(this.aes_key);

    const payload = {
      refresh_token: this.refresh_token,
      access_token: this.access_token,
      data: this.data,
    };

    const plaintext = new TextEncoder().encode(
      JSON.stringify(payload)
    );

    // --- cifrar payload ---
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await aesGcmEncrypt(keyBytes, iv, plaintext);

    // --- cifrar la AES con la propia AES (AES-en-AES) ---
    const ivAes = crypto.getRandomValues(new Uint8Array(12));
    const aesPlain = new TextEncoder().encode(this.aes_key);
    const aesCiphertext = await aesGcmEncrypt(keyBytes, ivAes, aesPlain);

    const out = {
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ciphertext),
      user_id: this.user_id,
      aes: {
        iv: b64uEncode(ivAes),
        ciphertext: b64uEncode(aesCiphertext),
      },
    };

    if (this.files && this.files.length > 0) {
      out.files = await encryptFiles(this.files, this.aes_key);
    }

    return out;
  }

  // ===============================
  // DECRYPT
  // ===============================
  static async decryptAES(encPacket, aes_key) {
    if (!encPacket?.iv || !encPacket?.ciphertext) {
      throw new Error("decryptAES: faltan iv/ciphertext");
    }
    if (typeof aes_key !== "string" || !aes_key) {
      throw new Error("decryptAES: aes_key invalida");
    }

    const keyBytes = Packet.normalizeAesKey(aes_key);

    const iv = b64uDecode(encPacket.iv);
    const ct = b64uDecode(encPacket.ciphertext);

    const plaintext = await aesGcmDecrypt(keyBytes, iv, ct);
    const decoded = JSON.parse(new TextDecoder().decode(plaintext));

    // agregamos user_id como hace el back
    decoded.user_id = encPacket.user_id;

    // --- AES interna (anti adulteracion) ---
    if (encPacket.aes) {
      const ivAes = b64uDecode(encPacket.aes.iv);
      const ctAes = b64uDecode(encPacket.aes.ciphertext);
      const aesPlain = await aesGcmDecrypt(keyBytes, ivAes, ctAes);
      decoded.aes = new TextDecoder().decode(aesPlain);
    }

    // --- files ---
    if (encPacket.files && encPacket.files.length > 0) {
      decoded.files = await decryptFiles(encPacket.files, aes_key);
    } else {
      decoded.files = [];
    }

    return decoded;
  }
}
