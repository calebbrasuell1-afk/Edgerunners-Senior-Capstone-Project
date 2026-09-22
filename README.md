# Senior-Capstone-Project
Analyzing cyber threats from log data (sample data will be provided)

In this project, you are required to look into large network traffic data to detect communications that do
not following the hand shaking mechanism of the TCP protocol. In particular, you need to list all of the
potential issues found on the log data and potentially used for future predictions of suspicious
communications. A visualization window allows users to look at the traffic data on a user selected range. 
The AI component/chatbox can be used to answer the user questions regarding the data. 
The student teams are required to link the visualization and the AI chatbox to support user understandings.

<img width="257" height="266" alt="image" src="https://github.com/user-attachments/assets/0d51862d-d190-4c6c-b596-058406f265dd" />


    Group Members          Roles
    Caleb Brasuell     Leader / Developer
    Jacob Couger       Customer Outreach
    Nicholas Richard   Developer / QA
    Michael Genovesi   Developer / QA
    Arya Monfared      Secondary Developer 

## **Group meetings - TUE/THURS: 2pm**

## **Upcoming schedules - THURSDAY: 2PM - FRIDAY: 2PM - SATURDAY: TBD**

It should automatically download the first 90 minutes of the data, and aggregate the data into a SQLite database, ready to be visualized. Please feel free to customize the codes, but you should at least extract the first 90 minutes of the raw data. 

The first 90-minute dataset is the first 105 files, from
`mypcap_20091103082335.pcap.xz` to `mypcap_20091103095256.pcap.xz`. That is
13:23:30 to 14:53:35 UTC on 2009-11-03, in the set1 folder.

How an AI-powered investigation may work:
    You look at the visualization and find something that stands out.
    You select the related hosts and/or the time window with a selection tool.
    You ask the AI assistant a question. Your selection is the scope of the answer.
    The assistant answers, and writes its answer back onto the visualization.
    Repeat until you both come to a conclusion.

    
Before developing the application, I recommend that you should spend some time to understand the data, research some network data visualization techniques, and draft out how the application is going to look like.



# Stage 1 
- [ ] Due date: Sept 27 (Sunday) before 11:59 PM
- [ ] Submit report (e.g., PDF) and presentation slides 
- [ ] Submit the URL
- [ ] The file names should include the stage and group_name, “stage#_group_name”. For example, stage1_MyGroup.pdf and stage1_MyGroup.pptx.
Description
Analyze potential target users and identify any function and performance requirement of your system.
- [ ] (i) First, in order to analyze the users, interview (e.g., zoom, call, email, etc.) at least four or five users who are not
taking CS4366. Be specific about the users, for example range of age, culture, computer/IT experience, attitude, and
anything you may think important. Prepare several questions and log interviews (multiple pages) and summarize them
(half page). 

- [ ] (ii) Refer to IEEE Std 830-1998 (IEEE Recommended Practice for Software Requirements Specifications;
pp.11 – 20 only) and fill out each section/sub-section. If a section/sub-section is not related to your project scope, you
can skip (e.g., 5.2.1.3 Hardware Interface). Here, you should explain why you skipped it. 

- [ ] (iii) In order to fill out sections/sub-sections (e.g., 5.3.2 Functions), you should identify the existing functions, and suggest new functions
and their features. List all the functions that your system should support. Consider any data requirement and data
input/output of your system. Explain in as much detail as possible, for example, function environment, constraint,
trade-off, and anything you may think important

# Deliverables

In this project, you should
Submit a PDF in IEEE conference format (two-column, 10 pt, letter size), minimum two pages excludingappendices. The report must include:
- [ ] Project description and motivation (1 or 2 paragraphs)
- [ ]  Interview summary (half page). Full interview log goes in an appendix, which may be single-column.
- [ ]  SRS based on the IEEE Std 830-1998
- [ ]  Project plan (bullet points): based on your interview findings, list the modules or features you will build with a brief explanation of each
- [ ]  Prepare a 10 – 15 minute presentation accordingly and present your system and receive feedback from the instructor and other classmates during the class. The presentation schedule will be announced later.

 ### http://www.math.uaa.alaska.edu/~afkjm/cs401/IEEE830.pdf - link to srs requirements

 ### https://docs.google.com/document/d/10P19Bv2b2z5NSZ3iyDrmJurHI75_lhUdEfXtOO2VjnY/edit?usp=sharing - link to requirement tracker



# Grading policy
Your project report and presentation should look professional in the sense of completeness, clarity, consistency, and
labeling. You should use pictures, graphs, and tables if they can help. You will be evaluated based on the following:

• Quality/Clarity of requirement specification

• Quality of interview questions and summary

• Quality of project report

• Quality of presentation (10 - 15 minutes)
