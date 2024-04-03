namespace System.Security.Encryption;

using System;

codeunit 50000 "RSA PSS Impl." implements SignatureAlgorithm, "Signature Algorithm v2"
{
    Access = Internal;
    InherentEntitlements = X;
    InherentPermissions = X;

    var
        DotNetRSA: DotNet RSA;

    procedure InitializeRSA(KeySize: Integer)
    begin
        DotNetRSA := DotNetRSA.Create(KeySize);
    end;

    procedure GetInstance(var DotNetAsymmetricAlgorithm: DotNet AsymmetricAlgorithm)
    begin
        DotNetAsymmetricAlgorithm := DotNetRSA;
    end;

    #region SignData
    [NonDebuggable]
    procedure SignData(XmlString: Text; DataInStream: InStream; HashAlgorithm: Enum "Hash Algorithm"; SignatureOutStream: OutStream)
    begin
        FromXmlString(XmlString);
        SignData(DataInStream, HashAlgorithm, SignatureOutStream);
    end;

    [NonDebuggable]
    procedure SignData(DataInStream: InStream; HashAlgorithm: Enum "Hash Algorithm"; SignatureOutStream: OutStream)
    var
        Bytes: DotNet Array;
        Signature: DotNet Array;
    begin
        if DataInStream.EOS() then
            exit;
        InStreamToArray(DataInStream, Bytes);
        SignData(Bytes, HashAlgorithm, Signature);
        ArrayToOutStream(Signature, SignatureOutStream);
    end;

    [NonDebuggable]
    local procedure SignData(Bytes: DotNet Array; HashAlgorithm: Enum "Hash Algorithm"; var Signature: DotNet Array)
    begin
        if Bytes.Length() = 0 then
            exit;
        TrySignData(Bytes, HashAlgorithm, Signature);
    end;

    [TryFunction]
    [NonDebuggable]
    local procedure TrySignData(Bytes: DotNet Array; HashAlgorithm: Enum "Hash Algorithm"; var Signature: DotNet Array)
    var
        DotNetHashAlgorithmName: DotNet HashAlgorithmName;
        DotNetRSASignaturePadding: DotNet RSASignaturePadding;
    begin
        HashAlgorithmEnumToDotNet(HashAlgorithm, DotNetHashAlgorithmName);
        Signature := DotNetRSA.SignData(Bytes, DotNetHashAlgorithmName, DotNetRSASignaturePadding.Pss);
    end;
    #endregion

    #region VerifyData
    [NonDebuggable]
    procedure VerifyData(XmlString: Text; DataInStream: InStream; HashAlgorithm: Enum "Hash Algorithm"; SignatureInStream: InStream): Boolean
    begin
        FromXmlString(XmlString);
        exit(VerifyData(DataInStream, HashAlgorithm, SignatureInStream));
    end;

    [NonDebuggable]
    procedure VerifyData(DataInStream: InStream; HashAlgorithm: Enum "Hash Algorithm"; SignatureInStream: InStream): Boolean
    var
        Bytes: DotNet Array;
        Signature: DotNet Array;
    begin
        if DataInStream.EOS() or SignatureInStream.EOS() then
            exit(false);
        InStreamToArray(DataInStream, Bytes);
        InStreamToArray(SignatureInStream, Signature);
        exit(VerifyData(Bytes, HashAlgorithm, Signature));
    end;

    [NonDebuggable]
    local procedure VerifyData(Bytes: DotNet Array; HashAlgorithm: Enum "Hash Algorithm"; Signature: DotNet Array): Boolean
    var
        Verified: Boolean;
    begin
        if Bytes.Length() = 0 then
            exit(false);
        Verified := TryVerifyData(Bytes, HashAlgorithm, Signature);
        if not Verified and (GetLastErrorText() <> '') then
            Error(GetLastErrorText());
        exit(Verified);
    end;

    [TryFunction]
    [NonDebuggable]
    local procedure TryVerifyData(Bytes: DotNet Array; HashAlgorithm: Enum "Hash Algorithm"; Signature: DotNet Array)
    var
        DotNetHashAlgorithmName: DotNet HashAlgorithmName;
        DotNetRSASignaturePadding: DotNet RSASignaturePadding;
    begin
        HashAlgorithmEnumToDotNet(HashAlgorithm, DotNetHashAlgorithmName);

        if not DotNetRSA.VerifyData(Bytes, Signature, DotNetHashAlgorithmName, DotNetRSASignaturePadding) then
            Error('');
    end;
    #endregion

    #region Encryption & Decryption
    [NonDebuggable]
    procedure Encrypt(XmlString: Text; PlainTextInStream: InStream; OaepPadding: Boolean; EncryptedTextOutStream: OutStream)
    var
        PlainTextBytes: DotNet Array;
        EncryptedTextBytes: DotNet Array;
        DotNetRSAEncryptionPadding: DotNet RSAEncryptionPadding;
    begin
        FromXmlString(XmlString);
        InStreamToArray(PlainTextInStream, PlainTextBytes);

        if OaepPadding then
            DotNetRSAEncryptionPadding := DotNetRSAEncryptionPadding.OaepSHA256
        else
            DotNetRSAEncryptionPadding := DotNetRSAEncryptionPadding.Pkcs1;

        EncryptedTextBytes := DotNetRSA.Encrypt(PlainTextBytes, DotNetRSAEncryptionPadding);
        ArrayToOutStream(EncryptedTextBytes, EncryptedTextOutStream);
    end;

    [NonDebuggable]
    procedure Decrypt(XmlString: Text; EncryptedTextInStream: InStream; OaepPadding: Boolean; DecryptedTextOutStream: OutStream)
    var
        EncryptedTextBytes: DotNet Array;
        DecryptedTextBytes: DotNet Array;
        DotNetRSAEncryptionPadding: DotNet RSAEncryptionPadding;
    begin
        FromXmlString(XmlString);
        InStreamToArray(EncryptedTextInStream, EncryptedTextBytes);
        if OaepPadding then
            DotNetRSAEncryptionPadding := DotNetRSAEncryptionPadding.OaepSHA256
        else
            DotNetRSAEncryptionPadding := DotNetRSAEncryptionPadding.Pkcs1;
        DecryptedTextBytes := DotNetRSA.Decrypt(EncryptedTextBytes, DotNetRSAEncryptionPadding);
        ArrayToOutStream(DecryptedTextBytes, DecryptedTextOutStream);
    end;
    #endregion

    #region XmlString
    [NonDebuggable]
    procedure ToXmlString(IncludePrivateParameters: Boolean): Text
    begin
        exit(DotNetRSA.ToXmlString(IncludePrivateParameters));
    end;

    [NonDebuggable]
    procedure FromXmlString(XmlString: Text)
    begin
        RSACryptoServiceProvider();
        DotNetRSA.FromXmlString(XmlString);
    end;
    #endregion

    [NonDebuggable]
    procedure FromSecretXmlString(XmlString: SecretText)
    begin
        RSACryptoServiceProvider();
        DotNetRSA.FromXmlString(XmlString.Unwrap());
    end;

    local procedure RSACryptoServiceProvider()
    begin
        DotNetRSA := DotNetRSA.Create(2048);
    end;

    [NonDebuggable]
    local procedure ArrayToOutStream(Bytes: DotNet Array; OutputOutStream: OutStream)
    var
        DotNetMemoryStream: DotNet MemoryStream;
    begin
        DotNetMemoryStream := DotNetMemoryStream.MemoryStream(Bytes);
        CopyStream(OutputOutStream, DotNetMemoryStream);
    end;

    [NonDebuggable]
    local procedure InStreamToArray(InputInStream: InStream; var Bytes: DotNet Array)
    var
        DotNetMemoryStream: DotNet MemoryStream;
    begin
        DotNetMemoryStream := DotNetMemoryStream.MemoryStream();
        CopyStream(DotNetMemoryStream, InputInStream);
        Bytes := DotNetMemoryStream.ToArray();
    end;

    local procedure HashAlgorithmEnumToDotNet(HashAlgorithm: Enum "Hash Algorithm"; var DotNetHashAlgorithmName: DotNet HashAlgorithmName)
    begin
        case
           HashAlgorithm of
            HashAlgorithm::MD5:
                DotNetHashAlgorithmName := DotNetHashAlgorithmName.MD5;
            HashAlgorithm::SHA1:
                DotNetHashAlgorithmName := DotNetHashAlgorithmName.SHA1;
            HashAlgorithm::SHA256:
                DotNetHashAlgorithmName := DotNetHashAlgorithmName.SHA256;
            HashAlgorithm::SHA384:
                DotNetHashAlgorithmName := DotNetHashAlgorithmName.SHA384;
            HashAlgorithm::SHA512:
                DotNetHashAlgorithmName := DotNetHashAlgorithmName.SHA512;
            else
                OnElseHashAlgorithmEnumToDotNet(HashAlgorithm, DotNetHashAlgorithmName);
        end;
    end;

    [IntegrationEvent(false, false)]
    local procedure OnElseHashAlgorithmEnumToDotNet(HashAlgorithm: Enum "Hash Algorithm"; var DotNetHashAlgorithmName: DotNet HashAlgorithmName)
    begin
    end;
}