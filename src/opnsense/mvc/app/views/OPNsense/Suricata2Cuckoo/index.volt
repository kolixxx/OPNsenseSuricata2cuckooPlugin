{#
Suricata2Cuckoo plugin UI
#}

<script>
$(document).ready(function() {
  function prettyJson(obj) {
    try { return JSON.stringify(obj, null, 2); } catch (e) { return String(obj); }
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
    $("#applyResult").addClass("hidden").text("");
    $("#applyAct").prop("disabled", true).text("Applying…");
    saveFormToEndpoint("/api/suricata2cuckoo/settings/set",'frm_GeneralSettings', function(){
      ajaxCall(url="/api/suricata2cuckoo/service/apply", sendData={}, callback=function(data,status) {
        $("#applyResult").removeClass("hidden").text(prettyJson(data));
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
      $("#applyResult").removeClass("hidden").text(prettyJson(data));
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

<div class="alert alert-info">
  <strong>Status:</strong> <span id="svcStatus">loading…</span>
  <div class="help-block">
    Apply will generate <code>/usr/local/etc/suricata/rules/file-extract.rules</code>, enable required IDS prerequisites and reload IDS rules.
  </div>
  <div class="help-block">
    Reserved local SID range: <code>1000001–1000999</code>.
  </div>
</div>

<div class="hidden alert alert-success" id="saveNotice">
  Settings saved.
</div>
<div class="hidden alert alert-default" id="applyResult"></div>

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

