//all used scripts here

$(document).ready(function(){
	function createBox(link) {
		$("body").append('<div id="popuper" onclick="javascript:remove();"><img id="popupimg" src="'+link+'"></div>');
		var wd = $("#popupimg").width();
		var ht = $("#popupimg").height();
		var dwd = $(document).width();
		var dht = $(document).height();
		$("#popupimg").css({"left": (dwd-wd)/2, "top": (dht-ht)/2});
	}

	$(".popimager").click(function(){
		var lk = $(this).attr("src");
		createBox(lk);
	});
});