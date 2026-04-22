{#
Suricata2Cuckoo plugin UI
#}

<script>
$(document).ready(function() {
  mapDataToFormUI({'frm_GeneralSettings':"/api/suricata2cuckoo/settings/get"}).done(function() {
    ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(data,status) {
      if (data && data.status !== undefined) {
        $("#svcStatus").text(data.status);
      }
    });
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
        $("#applyResult").removeClass("hidden").text(JSON.stringify(data));
        $("#applyAct").prop("disabled", false).text("Apply");
        ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(d,s) {
          if (d && d.status !== undefined) {
            $("#svcStatus").text(d.status);
          }
        });
      });
    });
  });

  $("#restartAct").click(function(){
    ajaxCall(url="/api/suricata2cuckoo/service/restart", sendData={}, callback=function(data,status) {
      $("#applyResult").removeClass("hidden").text(JSON.stringify(data));
      ajaxCall(url="/api/suricata2cuckoo/service/status", sendData={}, callback=function(d,s) {
        if (d && d.status !== undefined) {
          $("#svcStatus").text(d.status);
        }
      });
    });
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

