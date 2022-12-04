import * as zxcvbn from "zxcvbn";

import { CryptoService } from "../abstractions/crypto.service";
import { PasswordGenerationService as PasswordGenerationServiceAbstraction } from "../abstractions/passwordGeneration.service";
import { PolicyService } from "../abstractions/policy/policy.service.abstraction";
import { StateService } from "../abstractions/state.service";
import { PolicyType } from "../enums/policyType";
import { EFFLongWordList } from "../misc/wordlist";
import { EncString } from "../models/domain/enc-string";
import { GeneratedPasswordHistory } from "../models/domain/generated-password-history";
import { PasswordGeneratorOptions } from "../models/domain/password-generator-options";
import { PasswordGeneratorPolicyOptions } from "../models/domain/password-generator-policy-options";

const DefaultOptions: PasswordGeneratorOptions = {
  length: 14,
  ambiguous: false,
  number: true,
  minNumber: 1,
  uppercase: true,
  minUppercase: 0,
  lowercase: true,
  minLowercase: 0,
  special: false,
  minSpecial: 1,
  special1: false,
  minSpecial1: 1,
  special2: false,
  minSpecial2: 1,
  special3: false,
  minSpecial3: 1,
  type: "password",
  numWords: 3,
  wordSeparator: "-",
  capitalize: false,
  includeNumber: false,
};

const MaxPasswordsInHistory = 100;

export class PasswordGenerationService implements PasswordGenerationServiceAbstraction {
  constructor(
    private cryptoService: CryptoService,
    private policyService: PolicyService,
    private stateService: StateService
  ) {}

  async generatePassword(options: PasswordGeneratorOptions): Promise<string> {
    // overload defaults with given options
    const o = Object.assign({}, DefaultOptions, options);

    if (o.type === "passphrase") {
      return this.generatePassphrase(options);
    }

    // sanitize
    this.sanitizePasswordLength(o, true);

    const minLength: number = o.minUppercase + o.minLowercase + o.minNumber + o.minSpecial;
    if (o.length < minLength) {
      o.length = minLength;
    }

    const positions: string[] = [];
    if (o.lowercase && o.minLowercase > 0) {
      for (let i = 0; i < o.minLowercase; i++) {
        positions.push("l");
      }
    }
    if (o.uppercase && o.minUppercase > 0) {
      for (let i = 0; i < o.minUppercase; i++) {
        positions.push("u");
      }
    }
    if (o.number && o.minNumber > 0) {
      for (let i = 0; i < o.minNumber; i++) {
        positions.push("n");
      }
    }
    if (o.special && o.minSpecial > 0) {
      for (let i = 0; i < o.minSpecial; i++) {
        positions.push("s");
      }
    }
    if (o.special1 && o.minSpecial1 > 0) {
      for (let i = 0; i < o.minSpecial1; i++) {
        positions.push("x");
      }
    }
    if (o.special2 && o.minSpecial2 > 0) {
      for (let i = 0; i < o.minSpecial2; i++) {
        positions.push("y");
      }
    }
    if (o.special3 && o.minSpecial3 > 0) {
      for (let i = 0; i < o.minSpecial3; i++) {
        positions.push("e");
      }
    }
    while (positions.length < o.length) {
      positions.push("a");
    }

    // shuffle
    await this.shuffleArray(positions);

    // build out the char sets
    let allCharSet = "";

    let lowercaseCharSet = "abcdefghijkmnopqrstuvwxyz";
    if (o.ambiguous) {
      lowercaseCharSet += "l";
    }
    if (o.lowercase) {
      allCharSet += lowercaseCharSet;
    }

    let uppercaseCharSet = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    if (o.ambiguous) {
      uppercaseCharSet += "IO";
    }
    if (o.uppercase) {
      allCharSet += uppercaseCharSet;
    }

    let numberCharSet = "23456789";
    if (o.ambiguous) {
      numberCharSet += "01";
    }
    if (o.number) {
      allCharSet += numberCharSet;
    }

    // 漢字Top1000
    const specialCharSet =
      "日一国会人年大十二本中長出三同時政事自行社見月分議後前民生連五発間対上部東者党地合市業内相方四定今回新場金員九入選立開手米力学問高代明実円関決子動京全目表戦経通外最言氏現理調体化田当八六約主題下首意法不来作性的要用制治度務強気小七成期公持野協取都和統以機平総加山思家話世受区領多県続進正安設保改数記院女初北午指権心界支第産結百派点教報済書府活原先共得解名交資予川向際査勝面委告軍文反元重近千考判認画海参売利組知案道信策集在件団別物側任引使求所次水半品昨論計死官増係感特情投示変打男基私各始島直両朝革価式確村提運終挙果西勢減台広容必応演電歳住争談能無再位置企真流格有疑口過局少放税検藤町常校料沢裁状工建語球営空職証土与急止送援供可役構木割聞身費付施切由説転食比難防補車優夫研収断井何南石足違消境神番規術護展態導鮮備宅害配副算視条幹独警宮究育席輸訪楽起万着乗店述残想線率病農州武声質念待試族象銀域助労例衛然早張映限親額監環験追審商葉義伝働形景落欧担好退準賞訴辺造英被株頭技低毎医復仕去姿味負閣韓渡失移差衆個門写評課末守若脳極種美岡影命含福蔵量望松非撃佐核観察整段横融型白深字答夜製票況音申様財港識注呼渉達良響阪帰針専推谷古候史天階程満敗管値歌買突兵接請器士光討路悪科攻崎督授催細効図週積丸他及湾録処省旧室憲太橋歩離岸客風紙激否周師摘材登系批郎母易健黒火戸速存花春飛殺央券赤号単盟座青破編捜竹除完降超責並療従右修捕隊危採織森競拡故館振給屋介読弁根色友苦就迎走販園具左異歴辞将秋因献厳馬愛幅休維富浜父遺彼般未塁貿講邦舞林装諸夏素亡劇河遣航抗冷模雄適婦鉄寄益込顔緊類児余禁印逆王返標換久短油妻暴輪占宣背昭廃植熱宿薬伊江清習険頼僚覚吉盛船倍均億途圧芸許皇臨踏駅署抜壊債便伸留罪停興爆陸玉源儀波創障継筋狙帯延羽努固闘精則葬乱避普散司康測豊洋静善逮婚厚喜齢囲卒迫略承浮惑崩順紀聴脱旅絶級幸岩練押軽倒了庁博城患締等救執層版老令角絡損房募曲撤裏払削密庭徒措仏績築貨志混載昇池陣我勤為血遅抑幕居染温雑招奈季困星傷永択秀著徴誌庫弾償刊像功拠香欠更秘拒刑坂刻底賛塚致抱繰服犯尾描布恐寺鈴盤息宇項喪伴遠養懸戻街巨震願絵希越契掲躍棄欲痛触邸依籍汚縮還枚属笑互複慮郵束仲栄札枠似夕恵板列露沖探逃借緩節需骨射傾届曜遊迷夢巻購揮君燃充雨閉緒跡包駐貢鹿弱却端賃折紹獲郡併草徹飲貴埼衝焦奪雇災浦暮替析預焼簡譲称肉納樹挑章臓律誘紛貸至宗促慎控";
    if (o.special) {
      allCharSet += specialCharSet;
    }

    const specialCharSet1 =
      "あいうえおかきくけこさしすせそたちツテとなにぬねのはひふへほまみむめもやゆよらりるれろわをん"; // 平仮名
    if (o.special1) {
      allCharSet += specialCharSet1;
    }

    const specialCharSet2 =
      "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフへホマミムメモヤユヨラリルレロワヲン"; // 片仮名
    if (o.special2) {
      allCharSet += specialCharSet2;
    }

    const specialCharSet3 = "😊😭🐦🐻🐱🌲😀🙏💪👍🚀🚩🏆🎯🏁📣📢🔊🔔🌷🌱🌈"; // emoji
    if (o.special3) {
      allCharSet += specialCharSet3;
    }

    let password = "";
    for (let i = 0; i < o.length; i++) {
      let positionChars: string;
      switch (positions[i]) {
        case "l":
          positionChars = lowercaseCharSet;
          break;
        case "u":
          positionChars = uppercaseCharSet;
          break;
        case "n":
          positionChars = numberCharSet;
          break;
        case "s":
          positionChars = specialCharSet;
          break;
        case "x":
          positionChars = specialCharSet1;
          break;
        case "y":
          positionChars = specialCharSet2;
          break;
        case "e":
          positionChars = specialCharSet3;
          break;
        case "a":
          positionChars = allCharSet;
          break;
        default:
          break;
      }
      const arr = Array.from(positionChars);
      const randomCharIndex = await this.cryptoService.randomNumber(0, arr.length - 1);
      password += arr[randomCharIndex];
      // const randomCharIndex = await this.cryptoService.randomNumber(0, positionChars.length - 1);
      // password += positionChars.charAt(randomCharIndex);
    }

    return password;
  }

  async generatePassphrase(options: PasswordGeneratorOptions): Promise<string> {
    const o = Object.assign({}, DefaultOptions, options);

    if (o.numWords == null || o.numWords <= 2) {
      o.numWords = DefaultOptions.numWords;
    }
    if (o.wordSeparator == null || o.wordSeparator.length === 0 || o.wordSeparator.length > 1) {
      o.wordSeparator = " ";
    }
    if (o.capitalize == null) {
      o.capitalize = false;
    }
    if (o.includeNumber == null) {
      o.includeNumber = false;
    }

    const listLength = EFFLongWordList.length - 1;
    const wordList = new Array(o.numWords);
    for (let i = 0; i < o.numWords; i++) {
      const wordIndex = await this.cryptoService.randomNumber(0, listLength);
      if (o.capitalize) {
        wordList[i] = this.capitalize(EFFLongWordList[wordIndex]);
      } else {
        wordList[i] = EFFLongWordList[wordIndex];
      }
    }

    if (o.includeNumber) {
      await this.appendRandomNumberToRandomWord(wordList);
    }
    return wordList.join(o.wordSeparator);
  }

  async getOptions(): Promise<[PasswordGeneratorOptions, PasswordGeneratorPolicyOptions]> {
    let options = await this.stateService.getPasswordGenerationOptions();
    if (options == null) {
      options = Object.assign({}, DefaultOptions);
    } else {
      options = Object.assign({}, DefaultOptions, options);
    }
    await this.stateService.setPasswordGenerationOptions(options);
    const enforcedOptions = await this.enforcePasswordGeneratorPoliciesOnOptions(options);
    options = enforcedOptions[0];
    return [options, enforcedOptions[1]];
  }

  async enforcePasswordGeneratorPoliciesOnOptions(
    options: PasswordGeneratorOptions
  ): Promise<[PasswordGeneratorOptions, PasswordGeneratorPolicyOptions]> {
    let enforcedPolicyOptions = await this.getPasswordGeneratorPolicyOptions();
    if (enforcedPolicyOptions != null) {
      if (options.length < enforcedPolicyOptions.minLength) {
        options.length = enforcedPolicyOptions.minLength;
      }

      if (enforcedPolicyOptions.useUppercase) {
        options.uppercase = true;
      }

      if (enforcedPolicyOptions.useLowercase) {
        options.lowercase = true;
      }

      if (enforcedPolicyOptions.useNumbers) {
        options.number = true;
      }

      if (options.minNumber < enforcedPolicyOptions.numberCount) {
        options.minNumber = enforcedPolicyOptions.numberCount;
      }

      if (enforcedPolicyOptions.useSpecial) {
        options.special = true;
      }

      if (options.minSpecial < enforcedPolicyOptions.specialCount) {
        options.minSpecial = enforcedPolicyOptions.specialCount;
      }

      // Must normalize these fields because the receiving call expects all options to pass the current rules
      if (options.minSpecial + options.minNumber > options.length) {
        options.minSpecial = options.length - options.minNumber;
      }

      if (options.numWords < enforcedPolicyOptions.minNumberWords) {
        options.numWords = enforcedPolicyOptions.minNumberWords;
      }

      if (enforcedPolicyOptions.capitalize) {
        options.capitalize = true;
      }

      if (enforcedPolicyOptions.includeNumber) {
        options.includeNumber = true;
      }

      // Force default type if password/passphrase selected via policy
      if (
        enforcedPolicyOptions.defaultType === "password" ||
        enforcedPolicyOptions.defaultType === "passphrase"
      ) {
        options.type = enforcedPolicyOptions.defaultType;
      }
    } else {
      // UI layer expects an instantiated object to prevent more explicit null checks
      enforcedPolicyOptions = new PasswordGeneratorPolicyOptions();
    }
    return [options, enforcedPolicyOptions];
  }

  async getPasswordGeneratorPolicyOptions(): Promise<PasswordGeneratorPolicyOptions> {
    const policies = await this.policyService?.getAll(PolicyType.PasswordGenerator);
    let enforcedOptions: PasswordGeneratorPolicyOptions = null;

    if (policies == null || policies.length === 0) {
      return enforcedOptions;
    }

    policies.forEach((currentPolicy) => {
      if (!currentPolicy.enabled || currentPolicy.data == null) {
        return;
      }

      if (enforcedOptions == null) {
        enforcedOptions = new PasswordGeneratorPolicyOptions();
      }

      // Password wins in multi-org collisions
      if (currentPolicy.data.defaultType != null && enforcedOptions.defaultType !== "password") {
        enforcedOptions.defaultType = currentPolicy.data.defaultType;
      }

      if (
        currentPolicy.data.minLength != null &&
        currentPolicy.data.minLength > enforcedOptions.minLength
      ) {
        enforcedOptions.minLength = currentPolicy.data.minLength;
      }

      if (currentPolicy.data.useUpper) {
        enforcedOptions.useUppercase = true;
      }

      if (currentPolicy.data.useLower) {
        enforcedOptions.useLowercase = true;
      }

      if (currentPolicy.data.useNumbers) {
        enforcedOptions.useNumbers = true;
      }

      if (
        currentPolicy.data.minNumbers != null &&
        currentPolicy.data.minNumbers > enforcedOptions.numberCount
      ) {
        enforcedOptions.numberCount = currentPolicy.data.minNumbers;
      }

      if (currentPolicy.data.useSpecial) {
        enforcedOptions.useSpecial = true;
      }

      if (
        currentPolicy.data.minSpecial != null &&
        currentPolicy.data.minSpecial > enforcedOptions.specialCount
      ) {
        enforcedOptions.specialCount = currentPolicy.data.minSpecial;
      }

      if (
        currentPolicy.data.minNumberWords != null &&
        currentPolicy.data.minNumberWords > enforcedOptions.minNumberWords
      ) {
        enforcedOptions.minNumberWords = currentPolicy.data.minNumberWords;
      }

      if (currentPolicy.data.capitalize) {
        enforcedOptions.capitalize = true;
      }

      if (currentPolicy.data.includeNumber) {
        enforcedOptions.includeNumber = true;
      }
    });

    return enforcedOptions;
  }

  async saveOptions(options: PasswordGeneratorOptions) {
    await this.stateService.setPasswordGenerationOptions(options);
  }

  async getHistory(): Promise<GeneratedPasswordHistory[]> {
    const hasKey = await this.cryptoService.hasKey();
    if (!hasKey) {
      return new Array<GeneratedPasswordHistory>();
    }

    if ((await this.stateService.getDecryptedPasswordGenerationHistory()) == null) {
      const encrypted = await this.stateService.getEncryptedPasswordGenerationHistory();
      const decrypted = await this.decryptHistory(encrypted);
      await this.stateService.setDecryptedPasswordGenerationHistory(decrypted);
    }

    const passwordGenerationHistory =
      await this.stateService.getDecryptedPasswordGenerationHistory();
    return passwordGenerationHistory != null
      ? passwordGenerationHistory
      : new Array<GeneratedPasswordHistory>();
  }

  async addHistory(password: string): Promise<void> {
    // Cannot add new history if no key is available
    const hasKey = await this.cryptoService.hasKey();
    if (!hasKey) {
      return;
    }

    const currentHistory = await this.getHistory();

    // Prevent duplicates
    if (this.matchesPrevious(password, currentHistory)) {
      return;
    }

    currentHistory.unshift(new GeneratedPasswordHistory(password, Date.now()));

    // Remove old items.
    if (currentHistory.length > MaxPasswordsInHistory) {
      currentHistory.pop();
    }

    const newHistory = await this.encryptHistory(currentHistory);
    await this.stateService.setDecryptedPasswordGenerationHistory(currentHistory);
    return await this.stateService.setEncryptedPasswordGenerationHistory(newHistory);
  }

  async clear(userId?: string): Promise<void> {
    await this.stateService.setEncryptedPasswordGenerationHistory(null, { userId: userId });
    await this.stateService.setDecryptedPasswordGenerationHistory(null, { userId: userId });
  }

  passwordStrength(password: string, userInputs: string[] = null): zxcvbn.ZXCVBNResult {
    if (password == null || password.length === 0) {
      return null;
    }
    let globalUserInputs = ["bitwarden", "bit", "warden"];
    if (userInputs != null && userInputs.length > 0) {
      globalUserInputs = globalUserInputs.concat(userInputs);
    }
    // Use a hash set to get rid of any duplicate user inputs
    const finalUserInputs = Array.from(new Set(globalUserInputs));
    const result = zxcvbn(password, finalUserInputs);
    return result;
  }

  normalizeOptions(
    options: PasswordGeneratorOptions,
    enforcedPolicyOptions: PasswordGeneratorPolicyOptions
  ) {
    options.minLowercase = 0;
    options.minUppercase = 0;

    if (!options.length || options.length < 5) {
      options.length = 5;
    } else if (options.length > 128) {
      options.length = 128;
    }

    if (options.length < enforcedPolicyOptions.minLength) {
      options.length = enforcedPolicyOptions.minLength;
    }

    if (!options.minNumber) {
      options.minNumber = 0;
    } else if (options.minNumber > options.length) {
      options.minNumber = options.length;
    } else if (options.minNumber > 9) {
      options.minNumber = 9;
    }

    if (options.minNumber < enforcedPolicyOptions.numberCount) {
      options.minNumber = enforcedPolicyOptions.numberCount;
    }

    if (!options.minSpecial) {
      options.minSpecial = 0;
    } else if (options.minSpecial > options.length) {
      options.minSpecial = options.length;
    } else if (options.minSpecial > 9) {
      options.minSpecial = 9;
    }

    if (options.minSpecial < enforcedPolicyOptions.specialCount) {
      options.minSpecial = enforcedPolicyOptions.specialCount;
    }

    if (options.minSpecial + options.minNumber > options.length) {
      options.minSpecial = options.length - options.minNumber;
    }

    if (options.numWords == null || options.length < 3) {
      options.numWords = 3;
    } else if (options.numWords > 20) {
      options.numWords = 20;
    }

    if (options.numWords < enforcedPolicyOptions.minNumberWords) {
      options.numWords = enforcedPolicyOptions.minNumberWords;
    }

    if (options.wordSeparator != null && options.wordSeparator.length > 1) {
      options.wordSeparator = options.wordSeparator[0];
    }

    this.sanitizePasswordLength(options, false);
  }

  private capitalize(str: string) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  private async appendRandomNumberToRandomWord(wordList: string[]) {
    if (wordList == null || wordList.length <= 0) {
      return;
    }
    const index = await this.cryptoService.randomNumber(0, wordList.length - 1);
    const num = await this.cryptoService.randomNumber(0, 9);
    wordList[index] = wordList[index] + num;
  }

  private async encryptHistory(
    history: GeneratedPasswordHistory[]
  ): Promise<GeneratedPasswordHistory[]> {
    if (history == null || history.length === 0) {
      return Promise.resolve([]);
    }

    const promises = history.map(async (item) => {
      const encrypted = await this.cryptoService.encrypt(item.password);
      return new GeneratedPasswordHistory(encrypted.encryptedString, item.date);
    });

    return await Promise.all(promises);
  }

  private async decryptHistory(
    history: GeneratedPasswordHistory[]
  ): Promise<GeneratedPasswordHistory[]> {
    if (history == null || history.length === 0) {
      return Promise.resolve([]);
    }

    const promises = history.map(async (item) => {
      const decrypted = await this.cryptoService.decryptToUtf8(new EncString(item.password));
      return new GeneratedPasswordHistory(decrypted, item.date);
    });

    return await Promise.all(promises);
  }

  private matchesPrevious(password: string, history: GeneratedPasswordHistory[]): boolean {
    if (history == null || history.length === 0) {
      return false;
    }

    return history[history.length - 1].password === password;
  }

  // ref: https://stackoverflow.com/a/12646864/1090359
  private async shuffleArray(array: string[]) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = await this.cryptoService.randomNumber(0, i);
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  private sanitizePasswordLength(options: any, forGeneration: boolean) {
    let minUppercaseCalc = 0;
    let minLowercaseCalc = 0;
    let minNumberCalc: number = options.minNumber;
    let minSpecialCalc: number = options.minSpecial;

    if (options.uppercase && options.minUppercase <= 0) {
      minUppercaseCalc = 1;
    } else if (!options.uppercase) {
      minUppercaseCalc = 0;
    }

    if (options.lowercase && options.minLowercase <= 0) {
      minLowercaseCalc = 1;
    } else if (!options.lowercase) {
      minLowercaseCalc = 0;
    }

    if (options.number && options.minNumber <= 0) {
      minNumberCalc = 1;
    } else if (!options.number) {
      minNumberCalc = 0;
    }

    if (options.special && options.minSpecial <= 0) {
      minSpecialCalc = 1;
    } else if (!options.special) {
      minSpecialCalc = 0;
    }

    // This should never happen but is a final safety net
    if (!options.length || options.length < 1) {
      options.length = 10;
    }

    const minLength: number = minUppercaseCalc + minLowercaseCalc + minNumberCalc + minSpecialCalc;
    // Normalize and Generation both require this modification
    if (options.length < minLength) {
      options.length = minLength;
    }

    // Apply other changes if the options object passed in is for generation
    if (forGeneration) {
      options.minUppercase = minUppercaseCalc;
      options.minLowercase = minLowercaseCalc;
      options.minNumber = minNumberCalc;
      options.minSpecial = minSpecialCalc;
    }
  }
}
