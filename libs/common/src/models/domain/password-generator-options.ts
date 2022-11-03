export type PasswordGeneratorOptions = {
  length?: number;
  ambiguous?: boolean;
  uppercase?: boolean;
  minUppercase?: number;
  lowercase?: boolean;
  minLowercase?: number;
  number?: boolean;
  minNumber?: number;
  special?: boolean;
  minSpecial?: number;
  special1?: boolean; // あ
  minSpecial1?: number;
  special2?: boolean; // ア
  minSpecial2?: number;
  numWords?: number;
  wordSeparator?: string;
  capitalize?: boolean;
  includeNumber?: boolean;
  type?: "password" | "passphrase";
};
