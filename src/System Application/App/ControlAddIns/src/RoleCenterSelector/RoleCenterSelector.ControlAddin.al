// ------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// ------------------------------------------------------------------------------------------------

namespace System.Environment;

controladdin RoleCenterSelector
{
    RequestedHeight = 750;
    RequestedWidth = 560;
    VerticalStretch = true;
    HorizontalStretch = true;

    Scripts = 'https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.5.1.min.js',
              'https://static2.sharepointonline.com/files/fabric/office-ui-fabric-js/1.4.0/js/fabric.min.js',
              'src\RoleCenterSelector\js\RoleCenterSelector.js';
    StartupScript = 'src\RoleCenterSelector\js\Startup.js';
    RefreshScript = 'src\RoleCenterSelector\js\Refresh.js';
    RecreateScript = 'src\RoleCenterSelector\js\Recreate.js';
    StyleSheets = 'https://static2.sharepointonline.com/files/fabric/office-ui-fabric-js/1.4.0/css/fabric.min.css',
                  'https://static2.sharepointonline.com/files/fabric/office-ui-fabric-js/1.4.0/css/fabric.components.min.css',
                  'src\RoleCenterSelector\stylesheets\RoleCenterSelector.css';


    event ControlAddInReady();

    event OnAcceptAction();

    event OnProfileSelected(ProfileId: Text);

    procedure LoadRoleCenterFromJson(Json: Text);

    procedure LoadPageDataFromJson(Json: Text);

    procedure SetCurrentProfileId(ProfileId: Text);
}