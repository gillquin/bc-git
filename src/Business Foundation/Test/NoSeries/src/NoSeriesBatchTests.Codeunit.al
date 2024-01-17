namespace Microsoft.Test.Foundation.NoSeries;

using System.TestLibraries.Utilities;
using Microsoft.TestLibraries.Foundation.NoSeries;
using Microsoft.Foundation.NoSeries;

codeunit 134531 "No. Series Batch Tests"
{
    Subtype = Test;

    var
        Any: Codeunit Any;
        LibraryAssert: Codeunit "Library Assert";
        LibraryNoSeries: Codeunit "Library - No. Series";
        CannotAssignNewErr: Label 'You cannot assign new numbers from the number series %1.', Comment = '%1=No. Series Code';

    #region sequence
    [Test]
    procedure TestGetNextNoDefaultRunOut_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with 10 numbers
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, '1', '10');

        // [WHEN] We get the first 10 numbers from the No. Series
        // [THEN] The numbers match with 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
        for i := 1 to 10 do
            LibraryAssert.AreEqual(Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNo_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with a line going from 1-10, jumping 7 numbers at a time
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 7, '1', '10');

        // [WHEN] We get the first two numbers from the No. Series
        // [THEN] The numbers match with 1, 8
        LibraryAssert.AreEqual('1', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('8', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoWithLastNoUsed_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with a line going from 1-10, jumping 2 numbers at a time, with last used number 3
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 2, '1', '10', '3', 0D);

        // [WHEN] We get the first three new numbers from the No. Series
        // [THEN] The numbers match with 5, 7, 9
        LibraryAssert.AreEqual('5', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('7', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('9', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoDefaultOverFlow_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-5
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5');

        // [WHEN] We get the first 10 numbers from the No. Series
        // [THEN] The numbers match with A1, A2, A3, A4, A5, B1, B2, B3, B4, B5 (automatically switches from the first to the second series)
        for i := 1 to 5 do
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        for i := 1 to 5 do
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoAdvancedOverFlow_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-10, jumping 7 numbers at a time
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 7, 'A1', 'A10');
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 7, 'B1', 'B10');

        // [WHEN] We get the first 4 numbers from the No. Series
        // [THEN] The numbers match with A1, A8, B1, B8
        LibraryAssert.AreEqual('A01', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('A08', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('B01', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('B08', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoOverflowOutsideDate_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        TomorrowsWorkDate: Date;
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines, one only valid from WorkDate + 1
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        TomorrowsWorkDate := CalcDate('<+1D>', WorkDate());
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5', TomorrowsWorkDate);

        // [WHEN] We get the next number 5 times for WorkDate
        // [THEN] We get the numbers from the first line
        for i := 1 to 5 do
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number for WorkDate without throwing errors
        // [THEN] No number is returned
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesCode, WorkDate(), true), 'A number was returned when it should not have been');

        // [WHEN] We get the next number for WorkDate + 1
        // [THEN] We get the numbers from the second line
        for i := 1 to 5 do
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode, TomorrowsWorkDate), 'Number was not as expected');

        // [WHEN] We get the next number for WorkDate
        // [THEN] No other numbers are available
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoWithLine_Sequence()
    var
        NoSeriesLineA: Record "No. Series Line";
        NoSeriesLineB: Record "No. Series Line";
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-5
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5');

        NoSeriesLineA.SetRange("Series Code", NoSeriesCode);
        NoSeriesLineA.FindFirst();
        NoSeriesLineB.SetRange("Series Code", NoSeriesCode);
        NoSeriesLineB.FindLast();

        // [WHEN] We request numbers from each line
        // [THEN] We get the numbers for the specific line
        for i := 1 to 5 do begin
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesLineB, WorkDate()), 'Number was not as expected');
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesLineA, WorkDate()), 'Number was not as expected');
        end;

        // [WHEN] We get the next number for either line without throwing errors
        // [THEN] No number is returned
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesLineA, WorkDate(), true), 'A number was returned when it should not have been');
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesLineB, WorkDate(), true), 'A number was returned when it should not have been');
    end;

    [Test]
    procedure TestPeekNextNoDefaultRunOut_Sequence()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with 10 numbers
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateSequenceNoSeriesLine(NoSeriesCode, 1, 'A1Test', 'A10Test');

        // [WHEN] We peek the next number
        // [THEN] We get the first number
        LibraryAssert.AreEqual('A01TEST', NoSeriesBatch.PeekNextNo(NoSeriesCode), 'Initial number was not as expected');
        LibraryAssert.AreEqual('A01TEST', NoSeriesBatch.PeekNextNo(NoSeriesCode), 'Follow up call to PeekNextNo was not as expected');

        // [WHEN] We peek and get the next number 10 times
        // [THEN] The two match up
        for i := 1 to 10 do
            LibraryAssert.AreEqual(NoSeriesBatch.PeekNextNo(NoSeriesCode), NoSeriesBatch.GetNextNo(NoSeriesCode), 'GetNextNo and PeekNextNo are not aligned');

        // [WHEN] We peek the next number after the series has run out
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.PeekNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;
    #endregion

    #region normal
    [Test]
    procedure TestGetNextNoDefaultRunOut()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with 10 numbers
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, '1', '10');

        // [WHEN] We get the first 10 numbers from the No. Series
        // [THEN] The numbers match with 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
        for i := 1 to 10 do
            LibraryAssert.AreEqual(Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNo()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with a line going from 1-10, jumping 7 numbers at a time
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 7, '1', '10');

        // [WHEN] We get the first two numbers from the No. Series
        // [THEN] The numbers match with 1, 8
        LibraryAssert.AreEqual('1', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('8', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoWithLastNoUsed()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with a line going from 1-10, jumping 2 numbers at a time, with last used number 3
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 2, '1', '10', '3', 0D);

        // [WHEN] We get the first three new numbers from the No. Series
        // [THEN] The numbers match with 5, 7, 9
        LibraryAssert.AreEqual('5', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('7', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('9', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoDefaultOverFlow()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-5
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5');

        // [WHEN] We get the first 10 numbers from the No. Series
        // [THEN] The numbers match with A1, A2, A3, A4, A5, B1, B2, B3, B4, B5 (automatically switches from the first to the second series)
        for i := 1 to 5 do
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        for i := 1 to 5 do
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoAdvancedOverFlow()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-10, jumping 7 numbers at a time
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 7, 'A1', 'A10');
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 7, 'B1', 'B10');

        // [WHEN] We get the first 4 numbers from the No. Series
        // [THEN] The numbers match with A1, A8, B1, B8
        LibraryAssert.AreEqual('A01', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('A08', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('B01', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');
        LibraryAssert.AreEqual('B08', NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number from the No. Series
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoOverflowOutsideDate()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        TomorrowsWorkDate: Date;
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines, one only valid from WorkDate + 1
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        TomorrowsWorkDate := CalcDate('<+1D>', WorkDate());
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5', TomorrowsWorkDate);

        // [WHEN] We get the next number 5 times for WorkDate
        // [THEN] We get the numbers from the first line
        for i := 1 to 5 do
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode), 'Number was not as expected');

        // [WHEN] We get the next number for WorkDate without throwing errors
        // [THEN] No number is returned
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesCode, WorkDate(), true), 'A number was returned when it should not have been');

        // [WHEN] We get the next number for WorkDate + 1
        // [THEN] We get the numbers from the second line
        for i := 1 to 5 do
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesCode, TomorrowsWorkDate), 'Number was not as expected');

        // [WHEN] We get the next number for WorkDate
        // [THEN] No other numbers are available
        asserterror NoSeriesBatch.GetNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;

    [Test]
    procedure TestGetNextNoWithLine()
    var
        NoSeriesLineA: Record "No. Series Line";
        NoSeriesLineB: Record "No. Series Line";
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with two lines going from 1-5
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'A1', 'A5');
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'B1', 'B5');

        NoSeriesLineA.SetRange("Series Code", NoSeriesCode);
        NoSeriesLineA.FindFirst();
        NoSeriesLineB.SetRange("Series Code", NoSeriesCode);
        NoSeriesLineB.FindLast();

        // [WHEN] We request numbers from each line
        // [THEN] We get the numbers for the specific line
        for i := 1 to 5 do begin
            LibraryAssert.AreEqual('B' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesLineB, WorkDate()), 'Number was not as expected');
            LibraryAssert.AreEqual('A' + Format(i), NoSeriesBatch.GetNextNo(NoSeriesLineA, WorkDate()), 'Number was not as expected');
        end;

        // [WHEN] We get the next number for either line without throwing errors
        // [THEN] No number is returned
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesLineA, WorkDate(), true), 'A number was returned when it should not have been');
        LibraryAssert.AreEqual('', NoSeriesBatch.GetNextNo(NoSeriesLineB, WorkDate(), true), 'A number was returned when it should not have been');
    end;

    [Test]
    procedure TestPeekNextNoDefaultRunOut()
    var
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        i: Integer;
    begin
        Initialize();

        // [GIVEN] A No. Series with 10 numbers
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        LibraryNoSeries.CreateNormalNoSeriesLine(NoSeriesCode, 1, 'A1Test', 'A10Test');

        // [WHEN] We peek the next number
        // [THEN] We get the first number
        LibraryAssert.AreEqual('A01TEST', NoSeriesBatch.PeekNextNo(NoSeriesCode), 'Initial number was not as expected');
        LibraryAssert.AreEqual('A01TEST', NoSeriesBatch.PeekNextNo(NoSeriesCode), 'Follow up call to PeekNextNo was not as expected');

        // [WHEN] We peek and get the next number 10 times
        // [THEN] The two match up
        for i := 1 to 10 do
            LibraryAssert.AreEqual(NoSeriesBatch.PeekNextNo(NoSeriesCode), NoSeriesBatch.GetNextNo(NoSeriesCode), 'GetNextNo and PeekNextNo are not aligned');

        // [WHEN] We peek the next number after the series has run out
        // [THEN] An error is thrown
        asserterror NoSeriesBatch.PeekNextNo(NoSeriesCode);
        LibraryAssert.ExpectedError(StrSubstNo(CannotAssignNewErr, NoSeriesCode));
    end;


    [Test]
    procedure TestGetNextNoWithIncompleteLine()
    var
        NoSeriesLine: Record "No. Series Line";
        NoSeriesBatch: Codeunit "No. Series - Batch";
        NoSeriesCode: Code[20];
        StartingNo: Code[20];
        StartingNoLbl: Label 'SCI0000001';
    begin
        // init
        Initialize();

        // setup
        NoSeriesCode := CopyStr(UpperCase(Any.AlphabeticText(MaxStrLen(NoSeriesCode))), 1, MaxStrLen(NoSeriesCode));
        LibraryNoSeries.CreateNoSeries(NoSeriesCode);
        StartingNo := StartingNoLbl;

        NoSeriesLine.Validate("Series Code", NoSeriesCode);
        NoSeriesLine.Validate("Line No.", 10000);
        NoSeriesLine.Validate("Starting No.", StartingNo);
        NoSeriesLine.Validate("Last No. Used", '');
        NoSeriesLine.Validate("Last Date Used", 0D);
        NoSeriesLine.Insert();

        // exercise
        // verify
        LibraryAssert.AreEqual(StartingNo, NoSeriesBatch.GetNextNo(NoSeriesCode), 'not the first number');
        LibraryAssert.AreEqual(IncStr(StartingNo), NoSeriesBatch.GetNextNo(NoSeriesCode), 'not the second number');
    end;
    #endregion

    local procedure Initialize()
    begin
        Any.SetDefaultSeed();
    end;
}