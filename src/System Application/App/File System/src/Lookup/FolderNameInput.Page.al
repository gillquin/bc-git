// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace System.FileSystem;

page 9456 "Folder Name Input"
{
    ApplicationArea = All;
    Caption = 'Create Folder...';
    PageType = StandardDialog;
    Extensible = false;
    InherentPermissions = X;
    InherentEntitlements = X;

    layout
    {
        area(content)
        {
            field(FolderNameField; FolderName)
            {
                Caption = 'Folder Name';
            }
        }
    }

    var
        FolderName: Text;

    internal procedure GetFolderName(): Text
    begin
        exit(FolderName);
    end;
}
