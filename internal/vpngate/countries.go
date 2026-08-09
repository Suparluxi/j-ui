package vpngate

// VPNGate publishes English country names. Keep a small local display map so
// the panel can offer useful Chinese labels without another translation API.
var countryNamesZh = map[string]string{
	"AR": "阿根廷", "AU": "澳大利亚", "AT": "奥地利", "BE": "比利时", "BR": "巴西",
	"CA": "加拿大", "CL": "智利", "CN": "中国", "CO": "哥伦比亚", "CZ": "捷克",
	"DK": "丹麦", "EE": "爱沙尼亚", "FI": "芬兰", "FR": "法国", "DE": "德国", "GR": "希腊",
	"HK": "中国香港", "HU": "匈牙利", "IN": "印度", "ID": "印度尼西亚", "IE": "爱尔兰",
	"IL": "以色列", "IT": "意大利", "JP": "日本", "KR": "韩国", "MY": "马来西亚",
	"MX": "墨西哥", "NL": "荷兰", "NZ": "新西兰", "NO": "挪威", "PE": "秘鲁", "PH": "菲律宾",
	"PL": "波兰", "PT": "葡萄牙", "PY": "巴拉圭", "RO": "罗马尼亚", "RU": "俄罗斯", "SG": "新加坡",
	"SK": "斯洛伐克", "ZA": "南非", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士",
	"TW": "中国台湾", "TH": "泰国", "TR": "土耳其", "UA": "乌克兰", "AE": "阿联酋",
	"GB": "英国", "US": "美国", "VN": "越南",
}

func countryNameZh(code string) string {
	return countryNamesZh[code]
}
