.PHONY: all clean publish build

all: clean build publish

build: 
	@dotnet build -c Release

publish: build
	@dotnet publish Scanner/Scanner.csproj -r linux-x64 -c Release -o . \
		-p:PublishSingleFile=true

clean:
	@rm -rf bin/ obj/ ipk-l2l3-scan ipk-l2l3-scan.exe *.pdb