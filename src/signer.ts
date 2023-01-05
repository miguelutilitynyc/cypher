// https://gist.github.com/AndiDittrich/4629e7db04819244e843
import * as crypto from "crypto";

export default class Signer {
  constructor(private secretKey: string) {}
  encode(text: string) {
    // random initialization vector
    const iv = crypto.randomBytes(12);

    // random salt
    const salt = crypto.randomBytes(64);

    // derive key: 32 byte key length - in assumption the masterkey is a cryptographic and NOT a password there is no need for
    // a large number of iterations. It may can replaced by HKDF
    const key = crypto.pbkdf2Sync(this.secretKey, salt, 2145, 32, "sha512");

    // AES 256 GCM Mode
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    // encrypt the given text
    const encrypted = Buffer.concat([
      cipher.update(text, "utf8"),
      cipher.final(),
    ]);

    // extract the auth tag
    const tag = cipher.getAuthTag();

    // generate output
    return Buffer.concat([salt, iv, tag, encrypted]).toString("base64");
  }
  decode(data: string) {
    const bData = Buffer.from(data, "base64");

    // convert data to buffers
    const salt = bData.subarray(0, 64);
    const iv = bData.subarray(64, 76);
    const tag = bData.subarray(76, 92);
    const text = bData.subarray(92);

    // derive key using; 32 byte key length
    const key = crypto.pbkdf2Sync(this.secretKey, salt, 2145, 32, "sha512");

    // AES 256 GCM Mode
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    // encrypt the given text
    return decipher.update(text, undefined, "utf8") + decipher.final("utf8");
  }
}
