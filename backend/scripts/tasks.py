


tasks = {


    1 : "Sensitive Data Exposure Confidential Document Access a confidential document.",
    2 : "Improper Input Validation Zero Stars Give a devastating zero-star feedback to the store",
    3 : "Broken Access Control Admin Section Access the administration section of the store."
}


task_hints = {
    1 : [

        """
        
        Analyze and tamper with links in the application that deliver a file directly.
        """,
        """
 The file you are looking for is not protected in any way. Once you found it you can also access it.
        
        """
    ],

    2 : [

        "Before you invest time bypassing the API, you might want to play around with the UI a bit."
    
    ]
,

    3 : [
        "Inspect client-side routes or frontend JavaScript code to discover hidden administrative interfaces.",
        "Look for administrative routes such as /#/administration or admin components referenced in the client scripts."
    ]
}