using System.Collections.Generic;

namespace TestWep.Models
{
    public class AClass
    {
        public int Id { get; set; }
        public string AName { get; set; }
        public List<BClass> ListB { get; set; }
    }
}