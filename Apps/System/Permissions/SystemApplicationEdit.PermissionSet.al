// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace System.Security.AccessControl;

using System.Visualization;
using System.Privacy;
using System.Email;
using System.Text;
using System.Environment.Configuration;
using System.Globalization;
using System.Tooling;
using System.Integration.Word;

permissionset 22 "System Application - Edit"
{
    Access = Internal;
    Assignable = false;

    IncludedPermissionSets = "System Application - View",
                             "Cues and KPIs - Edit",
                             "Data Classification - Edit",
                             "Email - Edit",
                             "Entity Text - Edit",
                             "Guided Experience - Edit",
                             "Language - Edit",
#if not CLEAN19
#pragma warning disable AL0432
                             "SL Designer Subscribers - Edit",
#pragma warning restore AL0432
#endif
                             "Translation - Edit",
                             "Word Templates - Edit";
}
