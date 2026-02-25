docker cp 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\check_running.sh' 'popkorn-artifact-popkorn-1:/tmp/check_running.sh'
docker exec popkorn-artifact-popkorn-1 bash /tmp/check_running.sh
