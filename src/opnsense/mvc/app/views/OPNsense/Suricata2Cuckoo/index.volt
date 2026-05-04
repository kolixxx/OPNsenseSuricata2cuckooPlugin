{#
Suricata2Cuckoo plugin UI
#}

<script>
$(document).ready(function() {
  function prettyJson(obj) {
    try { return JSON.stringify(obj, null, 2); } catch (e) { return String(obj); }
  }

  function initWatchMethodPopover() {
    var $f = $('input[id="suricata2cuckoo.general.WatchMethod"]');
    if ($f.length === 0) {
      return;
    }
    try {
      $f.popover('destroy');
    } catch (e) { /* ignore */ }
    var body =
      '<p style="margin:0 0 .5em 0; max-width:300px;">The filestore watcher supports <strong>two</strong> method names (see <code>suricata2cuckoo.pl</code>).</p>' +
      '<ul style="margin:0; padding-left:1.2em; max-width:300px; text-align:left; font-size:12px;">' +
      '<li><code>polling</code> — works everywhere (default).</li>' +
      '<li><code>kqueue</code> — BSD kqueue; needs Perl <code>IO::KQueue</code> (falls back to polling if unavailable).</li>' +
      '<li>Case does not matter: <code>KQUEUE</code> is fine; the daemon uses <code>lc()</code>.</li>' +
      '<li>Any other text is treated as <strong>polling</strong>.</li>' +
      '</ul>';
    $f.popover({
      container: 'body',
      placement: 'right',
      trigger: 'focus',
      html: true,
      title: 'Watch method',
      content: body
    });
  }

  function initCuckooApiTokenReveal() {
    var $inp = $('input[id="suricata2cuckoo.general.CuckooApiToken"]');
    if ($inp.length === 0) {
      return;
    }
    $('#cuckooApiTokenToggle').remove();
    var $btn = $(
      '<button type="button" class="btn btn-default btn-xs" id="cuckooApiTokenToggle" ' +
        'title="Show or hide API token" style="margin-left:6px;vertical-align:middle">' +
        '<i class="fa fa-eye"></i></button>'
    );
    $inp.after($btn);
    $btn.on('click', function (e) {
      e.preventDefault();
      var isPwd = $inp.attr('type') === 'password';
      $inp.attr('type', isPwd ? 'text' : 'password');
      $btn.find('i').toggleClass('fa-eye', !isPwd).toggleClass('fa-eye-slash', isPwd);
      $btn.attr('title', isPwd ? 'Hide API token' : 'Show API token');
    });
  }

  function initProtocolsPopover() {
    var $f = $('input[id="suricata2cuckoo.general.Protocols"]');
    if ($f.length === 0) {
      return;
    }
    try {
      $f.popover('destroy');
    } catch (e) { /* ignore */ }
    var body =
      '<p style="margin:0 0 .5em 0; max-width:300px;">Suricata <strong>protocol</strong> keywords for generated file-extract rules. Use <strong>comma</strong> or <strong>space</strong> between entries.</p>' +
      '<ul style="margin:0; padding-left:1.2em; max-width:300px; text-align:left; font-size:12px;">' +
      '<li>Examples: <code>http</code>, <code>smtp</code>, <code>ftp</code>, <code>smb</code></li>' +
      '<li><code>HTTP</code> and <code>http</code> are equivalent; <strong>Apply</strong> stores lowercase.</li>' +
      '<li>Extra spaces are ignored.</li>' +
      '</ul>';
    $f.popover({
      container: 'body',
      placement: 'right',
      trigger: 'focus',
      html: true,
      title: 'Protocols',
      content: body
    });
  }

  function refreshEveFileinfo() {
    $("#eveFileinfo").text("loading…");
    ajaxCall(url="/api/suricata2cuckoo/logs/fileinfo?lines=2000", sendData={}, callback=function(data,status) {
      if (data && data.error !== undefined) {
        $("#eveFileinfo").text(String(data.error));
      } else if (data && data.output !== undefined) {
        var out = data.output;
        if (!out || String(out).trim() === "") {
          $("#eveFileinfo").text("(no matching fileinfo lines in the last " + (data.lines || "?") + " eve.json lines)");
        } else {
          $("#eveFileinfo").text(out);
        }
      } else {
        $("#eveFileinfo").text(prettyJson(data));
      }
    });
  }

  mapDataToFormUI({'frm_GeneralSettings':"/api/suricata2cuckoo/settings/get"}).done(function() {
    initProtocolsPopover();
    initWatchMethodPopover();
    initCuckooApiTokenReveal();
    ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(data,status) {
      if (data && data.status !== undefined) {
        $("#svcStatus").text(data.status);
      }
    });
    refreshEveFileinfo();
  });

  $("#saveAct").click(function(){
    saveFormToEndpoint("/api/suricata2cuckoo/settings/set",'frm_GeneralSettings', function(){
      $("#saveNotice").removeClass("hidden");
    });
  });

  $("#applyAct").click(function(){
    $("#applyResult").addClass("hidden");
    $("#applyResultBody").text("");
    $("#applyAct").prop("disabled", true).text("Applying…");
    saveFormToEndpoint("/api/suricata2cuckoo/settings/set",'frm_GeneralSettings', function(){
      ajaxCall(url="/api/suricata2cuckoo/service/apply", sendData={}, callback=function(data,status) {
        $("#applyResult").removeClass("hidden");
        $("#applyResultBody").text(prettyJson(data));
        $("#applyAct").prop("disabled", false).text("Apply");
        ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(d,s) {
          if (d && d.status !== undefined) {
            $("#svcStatus").text(d.status);
          }
        });
        refreshEveFileinfo();
      });
    });
  });

  $("#restartAct").click(function(){
    ajaxCall(url="/api/suricata2cuckoo/service/restart", sendData={}, callback=function(data,status) {
      $("#applyResult").removeClass("hidden");
      $("#applyResultBody").text(prettyJson(data));
      ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(d,s) {
        if (d && d.status !== undefined) {
          $("#svcStatus").text(d.status);
        }
      });
      refreshEveFileinfo();
    });
  });

  $("#refreshEveAct").click(function(){
    refreshEveFileinfo();
  });
});
</script>

<div class="alert alert-warning" style="margin-bottom:12px;">
  <strong>{{ lang._('Required manual step in IDS') }}</strong>
  <p style="margin:8px 0 0 0;">
    {{ lang._('Open Services → Intrusion Detection → Administration. In the Logging section, enable «Enable eve syslog output» and «Enable eve HTTP logging», then press Apply on that IDS page. This plugin does not change those two options; without them, Suricata may not log HTTP/file metadata the way you expect.') }}
  </p>
</div>

<div class="alert alert-info">
  <strong>Status:</strong> <span id="svcStatus">loading…</span>
  <div class="help-block">
    {{ lang._('Apply generates') }} <code>/usr/local/etc/suricata/rules/file-extract.rules</code>,
    {{ lang._('mirrors only the two IDS options below (EVE fileinfo + file-store) into Intrusion Detection, reloads IDS rules, and restarts Suricata and this service.') }}
  </div>
  <div class="help-block">
    <strong>{{ lang._('Minimum for correct file extraction → Cuckoo') }}</strong>
    <ul style="margin-top:0.5em; margin-bottom:0; padding-left:1.2em;">
      <li>{{ lang._('Complete the yellow IDS Administration step above (syslog EVE + HTTP), then return here.') }}</li>
      <li>{{ lang._('IDS: Suricata enabled and running on the interface(s) where traffic is inspected.') }}</li>
      <li>{{ lang._('For IPS (inline blocking), set Capture mode to Netmap or Divert under Services → Intrusion Detection → Settings (not PCAP-only IDS).') }}</li>
      <li>{{ lang._('Keep enabled on this page: "Enable file-store output" and "Enable EVE fileinfo (files)" — Apply writes these into IDS; the daemon only uploads what Suricata writes under the filestore path.') }}</li>
      <li>{{ lang._('Set Protocols and File extensions to match your traffic, then Apply. If you change IDS settings elsewhere, open this page and Apply once more.') }}</li>
      <li>{{ lang._('Routine messages use syslog (program suricata2cuckoo) — System → Log Files → General. /var/log/suricata2cuckoo.log holds daemon(8) / early Perl output after a proper service restart (rc.d uses --no-fork).') }}</li>
      <li>{{ lang._('Under filestore, Suricata only creates subfolders (e.g. two hex levels) after a file is actually extracted — an empty directory until matching traffic exists.') }}</li>
    </ul>
  </div>
  <div class="help-block">
    {{ lang._('Reserved local SID range:') }} <code>1000001–1000999</code>
  </div>
</div>

<div class="hidden alert alert-success" id="saveNotice">
  Settings saved.
</div>
<div class="hidden alert alert-info" id="applyResult" style="margin-top:10px;">
  <strong>{{ lang._('Last apply / restart response') }}</strong>
  <pre id="applyResultBody" style="margin:8px 0 0 0; white-space:pre-wrap; max-height:280px; overflow:auto; font-size:12px; background:transparent; border:none; padding:0;"></pre>
</div>

{{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_GeneralSettings'])}}

<hr/>
<button class="btn btn-primary" id="saveAct">{{ lang._('Save') }}</button>
<button class="btn btn-success" id="applyAct">{{ lang._('Apply') }}</button>
<button class="btn btn-default" id="restartAct">{{ lang._('Restart service') }}</button>

<hr/>
<div class="panel panel-default">
  <div class="panel-heading">
    <b>{{ lang._('Recent EVE fileinfo (tail/grep)') }}</b>
    <button class="btn btn-xs btn-default pull-right" id="refreshEveAct">{{ lang._('Refresh') }}</button>
  </div>
  <div class="panel-body">
    <div class="help-block">
      Shows the last matching <code>fileinfo</code> lines from <code>/var/log/suricata/eve.json</code> (best-effort).
    </div>
    <pre id="eveFileinfo" style="white-space: pre-wrap; max-height: 360px; overflow:auto;">loading…</pre>
  </div>
</div>

