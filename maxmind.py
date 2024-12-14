import geoip2.database
import pycountry

def query_asn(ip_address):
    # 请将下面的文件路径替换为你下载的ASN数据库文件路径
    database_path = './MaxMind/GeoLite2-ASN_20230804/GeoLite2-ASN.mmdb'
    reader = geoip2.database.Reader(database_path)

    try:
        response = reader.asn(ip_address)
        asn = response.autonomous_system_number
        organization = response.autonomous_system_organization

        return asn, organization

    except geoip2.errors.AddressNotFoundError:
        # print(f"{ip_address} IP地址未找到ASN信息。")
        return 0, ""

    reader.close()
    
def locate_ip(ip_address):
    # 请将下面的文件路径替换为你下载的GeoIP2数据库文件路径
    database_path = './MaxMind/GeoLite2-City_20230804/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_path)
    
    try:
        response = reader.city(ip_address)
        country = response.country.name
        country_alpha2 = response.country.iso_code  # 两位字母代码
        country_alpha3 = convert_alpha2_to_alpha3(country_alpha2)
        city = response.city.name
        latitude = response.location.latitude
        longitude = response.location.longitude
        
        return country, country_alpha2, country_alpha3, city, latitude, longitude
        
    except geoip2.errors.AddressNotFoundError:
        # print(f"{ip_address} IP地址未找到地理位置信息。")
        pass

    reader.close()

def locate_continent(ip_address):
    # 请将下面的文件路径替换为你下载的GeoIP2数据库文件路径
    database_path = './MaxMind/GeoLite2-City_20230804/GeoLite2-City.mmdb'
    reader = geoip2.database.Reader(database_path)
    
    try:
        response = reader.city(ip_address)
        country = response.country.name
        country_alpha2 = response.country.iso_code  # 两位字母代码
        country_alpha3 = convert_alpha2_to_alpha3(country_alpha2)
        city = response.city.name
        continent = response.continent.code
        latitude = response.location.latitude
        longitude = response.location.longitude
        
        return country, country_alpha2, country_alpha3, city,continent, latitude, longitude
        
    except geoip2.errors.AddressNotFoundError:
        # print(f"{ip_address} IP地址未找到地理位置信息。")
        pass 
    reader.close()

def convert_alpha2_to_alpha3(alpha2_code):
    try:
        country = pycountry.countries.get(alpha_2=alpha2_code)
        if country:
            alpha3_code = country.alpha_3
            return alpha3_code
        else:
            return "未找到对应的国家代码。"
    except AttributeError:
        return "无效的国家代码。"

if __name__ == "__main__":
    ip_address = "114.114.114.114"  # 你要定位的IP地址
    locate_ip(ip_address)
    query_asn(ip_address)
