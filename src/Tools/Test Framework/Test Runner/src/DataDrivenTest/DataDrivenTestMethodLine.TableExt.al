tableextension 130458 "Data Driven Test Method Line" extends "Test Method Line"
{
    fields
    {
        field(1000; "Data Input"; Text[1024])
        {
            Caption = 'Data Input';
            ToolTip = 'Data input for the test method line';
            DataClassification = CustomerContent;
        }
    }
}