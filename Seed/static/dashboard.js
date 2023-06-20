function controlPump(){
    var pumpStatus = document.getElementById('pump-status').value;
    
    var formData = new FormData();
    var xhr = new XMLHttpRequest();
    
    xhr.open('POST', '/control_pump', true);
    xhr.setRequestHeader('Content-Type', application/x-www-form-urlencoded');
    
    xhr.onload = function(){
        if (xhr.status === 200)
        {
        
        }
        else
        {
        
        }
    };
    
    xhr.send(params);
}
