// Copyright (c) 2024 Qewertyy, MIT License

import { createInterface } from "readline";
import * as crypto from "crypto";

class Encryption {
  PrivateKey: string;
  constructor() {
    this.PrivateKey = "AES"; // Change this
  }

  main() {
    console.log("1. Encrypt");
    console.log("2. Decrypt");

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Choose an option: ", (choice: string | number) => {
      choice = parseInt(choice as string);
      switch (choice) {
        case 1:
          console.log("Enter Text to Encrypt");
          rl.question("", (encryptTxt) => {
            const encryptedText = this.encrypt(encryptTxt.toString());
            console.log("Encrypted Text: " + encryptedText);
            rl.close();
          });
          break;
        case 2:
          console.log("Enter Text to Decrypt");
          rl.question("", (decryptTxt) => {
            const decryptedText = this.decrypt(decryptTxt.toString());
            console.log("Decrypted Text: " + decryptedText);
            rl.close();
          });
          break;
        default:
          console.log("Seriously?");
          rl.close();
          break;
      }
    });
  }

  AES_Encrypt(text: string, password: string) {
    const saltBytes = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const key = crypto.pbkdf2Sync(password, saltBytes, 1000, 32, "sha1");
    const iv = crypto.pbkdf2Sync(password, saltBytes, 1000, 16, "sha1");

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
  }

  AES_Decrypt(text: string, password: string) {
    try {
      const saltBytes = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
      const key = crypto.pbkdf2Sync(password, saltBytes, 1000, 32, "sha1");
      const iv = crypto.pbkdf2Sync(password, saltBytes, 1000, 16, "sha1");

      const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
      let decrypted = decipher.update(text, "base64", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch (error) {
      if ((error as any).code == "ERR_OSSL_BAD_DECRYPT") {
        throw new Error("Invalid Key");
      }
      throw error;
    }
  }

  encrypt(input: string) {
    const key = crypto
      .createHash("sha256")
      .update(this.PrivateKey, "utf8")
      .digest("hex");
    return this.AES_Encrypt(input, key);
  }

  decrypt(input: string) {
    const key = crypto
      .createHash("sha256")
      .update(this.PrivateKey, "utf8")
      .digest("hex");
    return this.AES_Decrypt(input, key);
  }
}

const encryption = new Encryption();
encryption.main();
export default encryption;