task :default => [:build, :exit]

SOURCES = "task_vaccine.c submodules/liblorgnette/lorgnette.c"
CC_FLAGS = ""
COMPILER = "clang"
$status = 0
# Tests subrake's namespace
TESTS_NAMESPACE = "task_vaccine_tests"
import "#{Dir.pwd}/tests/Rakefile"


desc "Clean up the environment"
task :clear do
	system("rm -Rf ./build")
end

desc "Finish"
task :exit do
	exit $status
end

def build_library(arches, dynamic)
	arch_string = "-arch " + arches.join(" -arch ")
	dir = "build"
	if (arches.count == 1) then
		dir = "build/#{arches[0]}"
	else
		dir = "build/fat"
	end
	system("mkdir -p ./#{dir}") if (!File.exists?(Dir.getwd + "/#{dir}"))

	if (dynamic) then
		system("#{COMPILER} #{arch_string} \
			-dynamiclib -single_module \
			-o ./#{dir}/task_vaccine.dylib \
			#{SOURCES}")
	else
		system("#{COMPILER} #{arch_string} -c #{SOURCES}")
		system("libtool -static -o ./#{dir}/task_vaccine.a *.o")
		system("rm *.o")
	end

	if ($status == 0) then
		$status = $?.exitstatus
	end
end

desc "Build everything"
task :all do
	Rake::Task["clear"].execute
	build_library(["x86_64"], true)
	build_library(["x86_64"], false)
	build_library(["i386"], true)
	build_library(["i386"], false)
	build_library(["i386", "x86_64"], true)
	build_library(["i386", "x86_64"], false)
end

# Testing

desc "Test the library"
task :test do
	Rake::Task["#{TESTS_NAMESPACE}:default"].invoke
end

# Dynamic library target

desc "General build"
task :build do
	build_library(["x86_64"], true)
end

desc "Build for x86_64"
task :build_64 do
	build_library(["x86_64"], true)
end

desc "Build for i386"
task :build_32 do
	build_library(["i386"], true)
end

desc "Build for x86_64 and i386"
task :build_fat do
	build_library(["i386", "x86_64"], true)
end

# Static library target

desc "General static build"
task :static do
	build_library(["x86_64"], false)
end

desc "Build static for x86_64"
task :static_64 do
	build_library(["x86_64"], false)
end

desc "Build static for i386"
task :static_32 do
	build_library(["i386"], false)
end

desc "Build static for x86_64 and i386"
task :static_fat do
	build_library(["i386", "x86_64"], false)
end
