// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace Microsoft.Foundation.NoSeries;

interface "No. Series - Batch"
{
    procedure SetInitialState(TempNoSeriesLine: Record "No. Series Line" temporary);

    procedure PeekNextNo(TempNoSeriesLine: Record "No. Series Line" temporary): Code[20];

    procedure GetNextNo(TempNoSeriesLine: Record "No. Series Line" temporary): Code[20];

    procedure SaveState(TempNoSeriesLine: Record "No. Series Line" temporary);

    procedure SaveState();
}
