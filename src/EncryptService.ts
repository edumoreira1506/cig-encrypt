import CryptoJS from 'crypto-js';

export default class EncryptService {
  private _encryptKey;

  constructor(encryptKey: string) {
    this._encryptKey = encryptKey;

    this.encrypt = this.encrypt.bind(this);
    this.decrypt = this.decrypt.bind(this);
    this.check = this.check.bind(this);
  }

  encrypt(originalString: string): string {
    return CryptoJS.AES.encrypt(originalString, this._encryptKey).toString();
  }

  decrypt(encryptedString: string): string {
    const bytes  = CryptoJS.AES.decrypt(encryptedString, this._encryptKey);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);

    return originalText;
  }

  check(originalString: string, encryptedString: string): boolean {
    return originalString === this.decrypt(encryptedString);
  }
}
