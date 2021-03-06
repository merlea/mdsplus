public fun FastCamCheckResolution(in _resolution)
{
	
	_values = [[1024,1024],[1024,512],[1024,256],[1024,128],[1024,64],[1024,32],[1024,16], 
			   [512,512],  [512,256], [512,128], [512,64],  [512,32], [512,16], 
			   [256,1024], [256,512], [256,256], [256,128], [256,64], [256,32], [256,16], 
			   [128,1024], [128,512], [128,256], [128,128], [128,64], [128,32], [128,16]];

	_string = ["1024x1024","1024x512","1024x256","1024x128","1024x64","1024x32","1024x16", 
			   "512x512"  ,"512x256" ,"512x128" ,"512x64"  ,"512x32" ,"512x16", 
			   "256x1024" ,"256x512" ,"256x256" ,"256x128" ,"256x64" ,"256x32" ,"256x16", 
			   "128x1024" ,"128x512" ,"128x256" ,"128x128" ,"128x64" ,"128x32" ,"128x16"];


	for( _i = 0; _i < 27; _i++)
	{
		if( _resolution == _string[_i] )
		{
			return ( _values[ *, _i ] );
		}
	}

	return ([-1, -1]);

}


