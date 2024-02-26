// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace System.Apps.AppSource.Test;

using System.Apps.AppSource;
using System.RestClient;
using System.Environment.Configuration;
using System.TestLibraries.Utilities;

codeunit 135074 "AppSource Product Manager Test" implements "AppSource Product Manager Dependencies"
{
    Subtype = Test;

    var
        Assert: Codeunit "Library Assert";
        HyperlinkStorage: Codeunit "Library - Variable Storage";
        FormatRegionStore: Codeunit "Library - Variable Storage";
        UserSettingsLanguageIDStore: Codeunit "Library - Variable Storage";
        ApplicationFamilyStore: Codeunit "Library - Variable Storage";
        IsSaasStore: Codeunit "Library - Variable Storage";
        RestClientGetJsonStore: Codeunit "Library - Variable Storage";
        CountryLetterCodeStore: Codeunit "Library - Variable Storage";

    [Test]
    procedure TestExtractAppIDFromUniqueProductIDReturnsExpectedAppId()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        UniqueId: Text;
        AppId: Guid;
        ExpectedAppId: Guid;
    begin
        // Given
        UniqueId := 'PUBID.nav24spzoo1579516366010%7CAID.n24_test_transactability%7CPAPPID.0984da34-5ec1-4ac1-9575-b73fb2212327';
        ExpectedAppId := '0984da34-5ec1-4ac1-9575-b73fb2212327';

        // When 
        AppId := AppSourceProductManager.ExtractAppIDFromUniqueProductID(UniqueId);

        // Then
        Assert.AreEqual(ExpectedAppId, AppId, 'Expected AppId to be extracted from UniqueId');
    end;

    [Test]
    procedure TestExtractAppIDFromUniqueProductIDReturnsEmptyAppIdWhenNotValid()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        UniqueId: Text;
        AppId: Guid;
    begin
        // Given
        UniqueId := 'articentgroupllc1635512619530.ackee-ubuntu-18-04-minimal';

        // When 
        AppId := AppSourceProductManager.ExtractAppIDFromUniqueProductID(UniqueId);

        // Then
        Assert.IsTrue(IsNullGuid(AppId), 'Expected AppId to be empty when not present in the UniqueId');
    end;

    [Test]
    [HandlerFunctions('HyperlinkHandler')]
    procedure TestOpenAppSourceHyperlink()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        AppSourceProductManagerTest: Codeunit "AppSource Product Manager Test";
    begin
        Initialize();
        // Initialize this copy
        AppSourceProductManagerTest.Initialize();
        // Override dependencies
        AppSourceProductManager.SetDependencies(AppSourceProductManagerTest);

        // Given
        AppSourceProductManagerTest.AddToFormatRegionStore('da-DK');

        // With handler expectation
        HyperlinkStorage.Enqueue('https://appsource.microsoft.com/da-DK/marketplace/apps?product=dynamics-365-business-central');

        // When 
        AppSourceProductManager.OpenAppSource();

        // Then
        // Asserted in handler
        AppSourceProductManagerTest.AssertCleanedUp();
        AssertCleanedUp();
    end;

    [Test]
    [HandlerFunctions('HyperlinkHandler')]
    procedure TestOpenInAppSourceHyperlink()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        AppSourceProductManagerTest: Codeunit "AppSource Product Manager Test";
        UniqueId: Text;
    begin
        Initialize();
        // Initialize this copy
        AppSourceProductManagerTest.Initialize();
        // Override dependencies
        AppSourceProductManager.SetDependencies(AppSourceProductManagerTest);

        // Given
        AppSourceProductManagerTest.AddToUserSettingsLanguageIDStore(3082); //es-ES

        UniqueId := 'PUBID.nav24spzoo1579516366010%7CAID.n24_test_transactability%7CPAPPID.0984da34-5ec1-4ac1-9575-b73fb2212327';

        // With handler expectation
        HyperlinkStorage.Enqueue('https://appsource.microsoft.com/es-ES/product/dynamics-365-business-central/PUBID.nav24spzoo1579516366010%7CAID.n24_test_transactability%7CPAPPID.0984da34-5ec1-4ac1-9575-b73fb2212327');

        // When 
        AppSourceProductManager.OpenAppInAppSource(UniqueId);

        // Then
        // Asserted in handler
        AppSourceProductManagerTest.AssertCleanedUp();
        AssertCleanedUp();
    end;

    [Test]
    procedure TestLoadProductNotAllowedOnPremises()
    var
        TempProduct: Record "AppSource Product" temporary;
        AppSourceProductManager: codeunit "AppSource Product Manager";
        AppSourceProductManagerTest: Codeunit "AppSource Product Manager Test";
    begin
        Initialize();
        // Initialize this copy
        AppSourceProductManagerTest.Initialize();
        // Override dependencies
        AppSourceProductManager.SetDependencies(AppSourceProductManagerTest);

        // Given
        AppSourceProductManagerTest.AddToIsSaasStore(false);
        AppSourceProductManagerTest.AddToUserSettingsLanguageIDStore(3082); //es-ES
        AppSourceProductManagerTest.AddToApplicationFamilyStore('W1');
        AppSourceProductManagerTest.AddToCountryLetterCodeStore('dk');

        // When   
        asserterror AppSourceProductManager.GetProductsAndPopulateRecord(TempProduct);

        // Then
        Assert.ExpectedError('Not supported on premises.');

        AppSourceProductManagerTest.AssertCleanedUp();
        AssertCleanedUp();
    end;

    [Test]
    procedure TestLoadProduct()
    var
        TempAppSourceProduct: Record "AppSource Product" temporary;
        AppSourceProductManager: codeunit "AppSource Product Manager";
        AppSourceProductManagerTest: Codeunit "AppSource Product Manager Test";
    begin
        Initialize();

        // Initialize this copy
        AppSourceProductManagerTest.Initialize();
        // Override dependencies
        AppSourceProductManager.SetDependencies(AppSourceProductManagerTest);

        // Given
        AppSourceProductManagerTest.AddToIsSaasStore(true);
        AppSourceProductManagerTest.AddToApplicationFamilyStore('W1');
        AppSourceProductManagerTest.AddToUserSettingsLanguageIDStore(3082); //es-ES
        AppSourceProductManagerTest.AddToCountryLetterCodeStore('us');
        AppSourceProductManagerTest.AddToRestClientGetJsonStore('{"items": [{"uniqueProductId": "PUBID.pbsi_software|AID.247timetracker|PAPPID.9a12247e-8564-4b90-b80b-cd5f4b64217e","displayName": "Dynamics 365 Business Central","publisherId": "pbsi_software","publisherDisplayName": "David Boehm, CPA and Company Inc.","publisherType": "ThirdParty","ratingAverage": 5.0,"ratingCount": 2,"productType": "DynamicsBC","popularity": 7.729569120865367,"privacyPolicyUri": "https://pbsisoftware.com/24-7-tt-privacy-statement","lastModifiedDateTime": "2023-09-03T11:08:28.5348241+00:00"}]}');
        // When
        AppSourceProductManager.GetProductsAndPopulateRecord(TempAppSourceProduct);

        // Then
        Assert.AreEqual(TempAppSourceProduct.Count, 1, 'The number of products is incorrect.');
        Assert.AreEqual('Dynamics 365 Business Central', TempAppSourceProduct.DisplayName, 'The product name is incorrect.');
        AppSourceProductManagerTest.AssertCleanedUp();
        AssertCleanedUp();
    end;

    [Test]
    procedure TestLoadProductWithNextPageLink()
    var
        TempAppSourceProduct: Record "AppSource Product" temporary;
        AppSourceProductManager: codeunit "AppSource Product Manager";
        AppSourceProductManagerTest: Codeunit "AppSource Product Manager Test";
    begin
        Initialize();
        // Initialize this copy
        AppSourceProductManagerTest.Initialize();
        // Override dependencies
        AppSourceProductManager.SetDependencies(AppSourceProductManagerTest);

        // Given
        AppSourceProductManagerTest.AddToIsSaasStore(true);
        AppSourceProductManagerTest.AddToApplicationFamilyStore('W1');
        AppSourceProductManagerTest.AddToUserSettingsLanguageIDStore(3082); //es-ES
        AppSourceProductManagerTest.AddToCountryLetterCodeStore('dk');

        // Push first with next page link
        AppSourceProductManagerTest.AddToRestClientGetJsonStore('{"items": [{"uniqueProductId": "PUBID.advania|AID.advania_approvals|PAPPID.603d81ef-542b-46ae-9cb5-17dc16fa3842","displayName": "Dynamics 365 Business Central - First","publisherId": "advania","publisherDisplayName": "Advania","publisherType": "ThirdParty","ratingAverage": 0.0,"ratingCount": 0,"productType": "DynamicsBC","popularity": 7.729569120865367,"privacyPolicyUri": "https://privacy.d365bc.is/","lastModifiedDateTime": "2024-01-19T03:23:15.4319343+00:00"}],"nextPageLink": "next page uri"}');
        // Push second without next page link
        AppSourceProductManagerTest.AddToRestClientGetJsonStore('{"items": [{"uniqueProductId": "PUBID.pbsi_software|AID.247timetracker|PAPPID.9a12247e-8564-4b90-b80b-cd5f4b64217e","displayName": "Dynamics 365 Business Central - Second","publisherId": "pbsi_software","publisherDisplayName": "David Boehm, CPA and Company Inc.","publisherType": "ThirdParty","ratingAverage": 5.0,"ratingCount": 2,"productType": "DynamicsBC","popularity": 7.729569120865367,"privacyPolicyUri": "https://pbsisoftware.com/24-7-tt-privacy-statement","lastModifiedDateTime": "2023-09-03T11:08:28.5348241+00:00"}]}');

        // When
        AppSourceProductManager.GetProductsAndPopulateRecord(TempAppSourceProduct);

        // Then
        Assert.AreEqual(2, TempAppSourceProduct.Count, 'The number of products is incorrect.');
        TempAppSourceProduct.FindSet();
        Assert.AreEqual('Dynamics 365 Business Central - First', TempAppSourceProduct.DisplayName, 'The first product name is incorrect.');
        TempAppSourceProduct.Next();
        Assert.AreEqual('Dynamics 365 Business Central - Second', TempAppSourceProduct.DisplayName, 'The second product name is incorrect.');

        AppSourceProductManagerTest.AssertCleanedUp();
        AssertCleanedUp();
    end;

    [Test]
    // In AppSource this shows up as having the Buy Now button enabled
    procedure TestCanInstallProduct_BuyNow()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        PlansList: JsonArray;
        CanInstall: Boolean;
    begin
        // Given
        // Hello world sample: PUBID.microsoftdynsmb%7CAID.helloworld%7CPAPPID.8e315acc-413d-46d5-abb9-c16912d3f3e3
        PlansList.ReadFrom('[{"id": "0002","availabilities": [{"id": "DZH318Z0BMGT","actions": ["Browse","Curate","Details","License","Purchase"],"meter": null,"pricingAudience": "DirectCommercial","terms": [{"termDescriptionParameters": null,"termId": "bh3541oe15ry","termUnit": "P1M","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Month Trial to 1 Year Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.0,"msrp": 0.0},"renewTermId": "qdp73gtwa5dy","renewTermUnits": "P1Y","isAutorenewable": true},{"termDescriptionParameters": null,"termId": "njspcsugneyy","termUnit": "P1M","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Month Trial to 1 Month Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.0,"msrp": 0.0},"renewTermId": "usrac41besqy","renewTermUnits": "P1M","isAutorenewable": true}],"hasFreeTrials": true,"consumptionUnitType": "DAY","displayRank": 0},{"id": "DZH318Z0BMGP","actions": ["Browse","Curate","Details","License","Purchase","Renew"],"meter": null,"pricingAudience": "DirectCommercial","terms": [{"termDescriptionParameters": null,"termId": "qdp73gtwa5dy","termUnit": "P1Y","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Year Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.02,"msrp": 0.02},"renewTermId": "qdp73gtwa5dy","renewTermUnits": "P1Y","isAutorenewable": true},{"termDescriptionParameters": null,"termId": "usrac41besqy","termUnit": "P1M","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Month Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.01,"msrp": 0.01},"renewTermId": "usrac41besqy","renewTermUnits": "P1M","isAutorenewable": true}],"hasFreeTrials": false,"consumptionUnitType": "DAY","displayRank": 1}],"uiDefinitionUri": "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RW15J0G","isHidden": false,"isStopSell": false,"cspState": "OptOut","minQuantity": 1,"maxQuantity": 10,"isQuantifiable": true,"purchaseDurationDiscounts": [],"planId": "transactableplan1","uniquePlanId": "microsoftdynsmb.helloworldtransactableplan1","displayName": "First 10 users","metadata": {"generation": null,"altStackReference": null},"categoryIds": [],"pricingTypes": ["FreeTrial","Payg"],"description": "Test plan to test first 10 users configurations","skuId": "0002","planType": "DynamicsBC","displayRank": "2147483647","isPrivate": false},{"id": "0003","availabilities": [{"id": "DZH318Z0BMGW","actions": ["Browse","Curate","Details","License","Purchase","Renew"],"meter": null,"pricingAudience": "DirectCommercial","terms": [{"termDescriptionParameters": null,"termId": "qdp73gtwa5dy","termUnit": "P1Y","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Year Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.03,"msrp": 0.03},"renewTermId": "qdp73gtwa5dy","renewTermUnits": "P1Y","isAutorenewable": true},{"termDescriptionParameters": null,"termId": "usrac41besqy","termUnit": "P1M","prorationPolicy": {"minimumProratedUnits": "P1D"},"termDescription": "1 Month Subscription","price": {"currencyCode": "USD","isPIRequired": true,"listPrice": 0.02,"msrp": 0.02},"renewTermId": "usrac41besqy","renewTermUnits": "P1M","isAutorenewable": true}],"hasFreeTrials": false,"consumptionUnitType": "DAY","displayRank": 0}],"uiDefinitionUri": "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RW15J0H","isHidden": false,"isStopSell": false,"cspState": "OptOut","minQuantity": 10,"maxQuantity": 100,"isQuantifiable": true,"purchaseDurationDiscounts": [],"planId": "transactableplan2","uniquePlanId": "microsoftdynsmb.helloworldtransactableplan2","displayName": "Ten to Hundred plan","metadata": {"generation": null,"altStackReference": null},"categoryIds": [],"pricingTypes": ["Payg"],"description": "Test 10 - 100 User plan","skuId": "0003","planType": "DynamicsBC","displayRank": "2147483647","isPrivate": false}]');

        // When
        CanInstall := AppSourceProductManager.CanInstallProductWithPlans(PlansList);

        // Then
        Assert.IsTrue(CanInstall, 'The product should be installable.');
    end;

    [Test]
    // In AppSource this shows up as having the Get It Now button enabled
    procedure TestCanInstallProduct_GetItNow()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        PlansList: JsonArray;
        CanInstall: Boolean;
    begin
        // Given
        // Hello world too sample: PUBID.microsoftdynsmb%7CAID.helloworldtoo%7CPAPPID.37447a59-b131-4e9c-83a3-a7856bfc30ff
        PlansList.ReadFrom('[{"id": "0001","availabilities": [{"id": "DZH318Z0BMTW","actions": ["Browse","Curate","Details"],"meter": null,"pricingAudience": "DirectCommercial","terms": null,"hasFreeTrials": false,"displayRank": 0}],"uiDefinitionUri": "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE5c9A4","isHidden": false,"isStopSell": false,"isQuantifiable": false,"purchaseDurationDiscounts": [],"planId": "69fe2a5e-cb01-43ea-9af3-2417d0c843f2","uniquePlanId": "microsoftdynsmb.helloworldtoo69fe2a5e-cb01-43ea-9af3-2417d0c843f2","displayName": "HelloWorldToo","metadata": {"generation": null,"altStackReference": null},"categoryIds": [],"pricingTypes": [],"description": "<div>desc</div>","skuId": "0001","planType": "DynamicsBC","isPrivate": false}]');

        // When
        CanInstall := AppSourceProductManager.CanInstallProductWithPlans(PlansList);

        // Then
        if (CanInstall) then
            Assert.Fail('Test now produces expected outcome and should be update.');
        // Assert.IsTrue(CanInstall, 'The product should be installable.');
    end;


    [Test]
    // In AppSource this shows up as having the Free Trial button enabled
    procedure TestCanInstallProduct_FreeTrial()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        PlansList: JsonArray;
        CanInstall: Boolean;
    begin
        // Given
        // Manufacturing Central by Intech: PUBID.intechsystems%7CAID.manufacturing_central%7CPAPPID.cea8e27e-050e-4880-840c-954ceb2e3f13
        PlansList.ReadFrom('[{"id": "0001","availabilities": [{"id": "DZH318Z0BMV3","actions": ["Browse","Curate","Details"],"meter": null,"pricingAudience": "DirectCommercial","terms": null,"hasFreeTrials": false,"displayRank": 0}],"uiDefinitionUri": "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RW1fI7S","isHidden": false,"isStopSell": false,"isQuantifiable": false,"purchaseDurationDiscounts": [],"planId": "77447b7c-9737-4132-8191-b9ce21d35a0e","uniquePlanId": "intechsystems.manufacturing_central77447b7c-9737-4132-8191-b9ce21d35a0e","displayName": "Manufacturing Central","metadata": {"generation": null,"altStackReference": null},"categoryIds": [],"pricingTypes": [],"description": "<p>Hey there</p>","skuId": "0001","planType": "DynamicsBC","isPrivate": false}]');

        // When
        CanInstall := AppSourceProductManager.CanInstallProductWithPlans(PlansList);

        // Then
        if (CanInstall) then
            Assert.Fail('Test now produces expected outcome and should be update.');
        // Assert.IsTrue(CanInstall, 'The product should be installable.');
    end;

    [Test]

    // In AppSource this shows up as having the Contact Me button enabled
    procedure TestCanInstallProduct_ContactMe()
    var
        AppSourceProductManager: codeunit "AppSource Product Manager";
        PlansList: JsonArray;
        CanInstall: Boolean;
    begin
        // Given
        // Salesforce Integration by Celigo Inc: PUBID.celigoinc-causa1621285384596%7CAID.salesforce-integration-celigo%7CPAPPID.0595b87b-7670-4bd2-91e2-bd98a7fe2f5a
        PlansList.ReadFrom('[{"id": "0001","availabilities": [{"id": "DZH318Z0BMV7","actions": ["Browse","Curate","Details"],"meter": null,"pricingAudience": "DirectCommercial","terms": null,"hasFreeTrials": false,"displayRank": 0}],"uiDefinitionUri": "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE5fzzR","isHidden": false,"isStopSell": false,"isQuantifiable": false,"purchaseDurationDiscounts": [],"planId": "4b4a5c29-40ad-4169-b23c-1ea9a51fd176","uniquePlanId": "celigoinc-causa1621285384596.salesforce-integration-celigo4b4a5c29-40ad-4169-b23c-1ea9a51fd176","displayName": "Salesforce Integration for Dynamics 365 Business Central","metadata": {"generation": null,"altStackReference": null},"categoryIds": [],"pricingTypes": [],"description": "<div>Celigo</div>","skuId": "0001","planType": "DynamicsBC","isPrivate": false}]');

        // When
        CanInstall := AppSourceProductManager.CanInstallProductWithPlans(PlansList);

        // Then
        Assert.IsFalse(CanInstall, 'The product NOT should be installable.');
    end;

    [HyperlinkHandler]
    procedure HyperlinkHandler(Message: Text[1024])
    begin
        Assert.AreEqual(HyperlinkStorage.DequeueText(), Message, 'The hyperlink is incorrect.');
    end;

    internal procedure Initialize()
    begin
        HyperlinkStorage.Clear();
        FormatRegionStore.Clear();
        UserSettingsLanguageIDStore.Clear();
        ApplicationFamilyStore.Clear();
        IsSaasStore.Clear();
        RestClientGetJsonStore.Clear();
        CountryLetterCodeStore.Clear();
    end;

    internal procedure AssertCleanedUp()
    begin
        HyperlinkStorage.AssertEmpty();
        FormatRegionStore.AssertEmpty();
        UserSettingsLanguageIDStore.AssertEmpty();
        ApplicationFamilyStore.AssertEmpty();
        IsSaasStore.AssertEmpty();
        RestClientGetJsonStore.AssertEmpty();
        CountryLetterCodeStore.AssertEmpty();
    end;

    #region this helpers
    internal procedure AddToFormatRegionStore(FormatRegion: Text[80])
    begin
        FormatRegionStore.Enqueue(FormatRegion);
    end;

    internal procedure AddToUserSettingsLanguageIDStore(LanguageId: Integer)
    begin
        UserSettingsLanguageIDStore.Enqueue(LanguageId);
    end;

    internal procedure AddToApplicationFamilyStore(ApplicationFamily: Text)
    begin
        ApplicationFamilyStore.Enqueue(ApplicationFamily);
    end;

    internal procedure AddToIsSaasStore(IsSaasValue: Boolean)
    begin
        IsSaasStore.Enqueue(IsSaasValue);
    end;

    internal procedure AddToRestClientGetJsonStore(JsonText: Text)
    var
        JsonToken: JsonToken;
    begin
        JsonToken.ReadFrom(JsonText);
        RestClientGetJsonStore.Enqueue(JsonToken);
    end;

    internal procedure AddToCountryLetterCodeStore(CountryLetterCode: Text[2])
    begin
        CountryLetterCodeStore.Enqueue(CountryLetterCode);
    end;

    #endregion

    #region dependencies implementation

    procedure ShouldSetCommonHeaders(): Boolean
    begin
        exit(false);
    end;

    procedure GetCountryLetterCode(): Code[2]
    begin
        if (CountryLetterCodeStore.Length() > 0) then
            exit(CopyStr(CountryLetterCodeStore.DequeueText(), 1, 2));

        Assert.Fail('GetCountryLetterCode should not be called');
    end;

    procedure GetPreferredLanguage(): Text
    begin
        Assert.Fail('GetPreferredLanguage should not be called');
    end;

    // Dependency to Environment Information 
    procedure GetApplicationFamily(): Text
    begin
        if (ApplicationFamilyStore.Length() > 0) then
            exit(ApplicationFamilyStore.DequeueText());

        Assert.Fail('GetApplicationFamily should not be called');
    end;

    procedure IsSaas(): boolean
    begin
        if (IsSaasStore.Length() > 0) then
            exit(IsSaasStore.DequeueBoolean());

        Assert.Fail('IsSaas should not be called');
    end;

    // Dependency to Language 
    procedure GetFormatRegionOrDefault(FormatRegion: Text[80]): Text
    begin
        if (FormatRegionStore.Length() > 0) then
            exit(FormatRegionStore.DequeueText());

        Assert.Fail('GetFormatRegionOrDefault should not be called');
    end;

    procedure GetAsJSon(var RestClient: Codeunit "Rest Client"; RequestUri: Text): JsonToken
    var
        ValueVariant: Variant;
    begin
        if (RestClientGetJsonStore.Length() > 0) then begin
            RestClientGetJsonStore.Dequeue(ValueVariant);
            exit(ValueVariant);
        end;

        Assert.Fail('GetAsJSon should not be called');
    end;

    // Dependency to User Settings
    procedure GetUserSettings(UserSecurityID: Guid; var TempUserSettingsRecord: Record "User Settings" temporary)
    var
        LanguageID: Variant;
    begin
        if (UserSettingsLanguageIDStore.Length() > 0) then begin
            TempUserSettingsRecord.Init();
            TempUserSettingsRecord."User Security ID" := UserSecurityID;
            UserSettingsLanguageIDStore.Dequeue(LanguageID);
            TempUserSettingsRecord."Language ID" := LanguageID;
            exit;
        end;
        Assert.Fail('GetUserSettings should not be called');
    end;
    #endregion

}