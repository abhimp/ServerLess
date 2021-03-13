curl "http://localhost:9087/cgi-hotel-reservation/frontend/recommendations?require=price&lat=38.0235&lon=-122.095" 
echo
curl "http://localhost:9087/cgi-hotel-reservation/frontend/hotels?inDate=2015-04-09&outDate=2015-04-10&lon=-122.4071&lat=37.7834"
echo 
curl "http://localhost:9087/cgi-hotel-reservation/frontend/user?username=Cornell_0&password=0000000000"
echo 
curl "http://localhost:9087/cgi-hotel-reservation/frontend/reservation?inDate=2015-04-09&outDate=2015-04-10&hotelId=1&customerName=foobartest&username=Cornell_0&password=0000000000&number=1"
echo