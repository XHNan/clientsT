import Domain from "./domain-base";

export class PasswordGeneratorPolicyOptions extends Domain {
  defaultType = "";
  minLength = 0;
  useUppercase = false;
  useLowercase = false;
  useNumbers = false;
  numberCount = 0;
  useSpecial = false;
  useSpecial1 = false;
  useSpecial2 = false;
  specialCount = 0;
  specialCount1 = 0;
  specialCount2 = 0;
  minNumberWords = 0;
  capitalize = false;
  includeNumber = false;

  inEffect() {
    return (
      this.defaultType !== "" ||
      this.minLength > 0 ||
      this.numberCount > 0 ||
      this.specialCount > 0 ||
      this.useUppercase ||
      this.useLowercase ||
      this.useNumbers ||
      this.useSpecial ||
      this.useSpecial1 ||
      this.useSpecial2 ||
      this.minNumberWords > 0 ||
      this.capitalize ||
      this.includeNumber
    );
  }
}
