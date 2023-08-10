// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace System.Security.AccessControl;

using System.Azure.ActiveDirectory;
using System.Environment.Configuration;

entitlement "Dynamics 365 - Accountant Hub"
{
    Type = PerUserServicePlan;
    Id = '5d60ea51-0053-458f-80a8-b6f426a1a0c1';

#pragma warning disable AL0684
    ObjectEntitlements = "Application Objects - Exec",
                         "System Application - Basic",
                         "Azure AD Plan - Admin",
                         "Security Groups - Admin",
                         "Exten. Mgt. - Admin",
                         "Feature Key - Admin";
#pragma warning restore
}
