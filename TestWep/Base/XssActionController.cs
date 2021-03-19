using Microsoft.Security.Application;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Web.Mvc;

namespace TestWep.Base
{
    public class XssActionController
    {
        private static XssActionController instance;
        public static XssActionController Instance => instance = instance ?? new XssActionController();
        public XssActionController()
        {
            instance = this;
        }
        public void InvokeAction(ActionExecutingContext filterContext)
        {
            Dictionary<string, object> changeDictionary = new Dictionary<string, object>();
            //XssControl(filterContext.ActionParameters);
            foreach (var para in filterContext.ActionParameters)
            {
                if (para.Value?.GetType() == typeof(string))
                {

                    var value = para.Value as string;
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        value = Sanitizer.GetSafeHtmlFragment(value);
                        changeDictionary.Add(para.Key, value);
                    }
                }
                else if (para.Value != null)
                {
                    var ty = para.Value.ToString();
                    if (ty != null && (para.Value?.GetType().IsClass == true || ty.Contains("{")))
                    {
                        var clss = para.Value?.GetType();
                        var obj = clss.Assembly.CreateInstance(clss.FullName);
                        try
                        {
                            var vls = clss.GetProperties();
                            foreach (PropertyInfo item in vls)
                            {
                                var pItem = item.GetValue(para.Value, null)?.GetType();
                                if (pItem != null && pItem.Name.Contains("List"))
                                {
                                    IList oTheList = item.GetValue(para.Value, null) as IList;
                                    foreach (var altPara in oTheList)
                                    {
                                        var altclss = altPara?.GetType();
                                        var altobj = altclss.Assembly.CreateInstance(altclss.FullName);
                                        var altvls = altclss.GetProperties();
                                        foreach (PropertyInfo altitem in altvls)
                                        {
                                            var yvue = altitem.GetValue(altPara, null).ToString();
                                            if (yvue.Contains("deneme"))
                                                yvue = "deneme1";

                                            var isxss = !string.IsNullOrEmpty(Regex.Match(yvue, @"<|>|(|)&lt|%3c|script")?.Value);
                                            if (isxss)
                                            {
                                                var vlue = Sanitizer.GetSafeHtmlFragment(altitem.GetValue(altPara, null).ToString()).Replace("script", "");
                                                SetValue(altobj, altitem.Name, vlue);
                                            }
                                            else
                                            {
                                                SetValue(altobj, altitem.Name, yvue);
                                            }
                                        }

                                    }
                                    Type entityType = obj.GetType();
                                    PropertyInfo propertyInfo = entityType.GetProperty(item.Name);
                                    propertyInfo.SetValue(obj, oTheList, null);
                                }
                                else if (pItem != null && para.Value != null)
                                {
                                    var yvue = item.GetValue(para.Value, null).ToString();
                                    var isxss = !string.IsNullOrEmpty(Regex.Match(yvue, @"<|>|(|)&lt|%3c|script")?.Value);
                                    if (isxss)
                                    {
                                        var vlue = Sanitizer.GetSafeHtmlFragment(item.GetValue(para.Value, null).ToString()).Replace("script", "");
                                        SetValue(obj, item.Name, vlue);
                                    }
                                    else
                                    {
                                        SetValue(obj, item.Name, yvue);
                                    }

                                }
                            }
                            changeDictionary.Add(para.Key, obj);

                        }
                        catch (Exception ex)
                        {
                            if (changeDictionary?.Count > 0)
                            {
                                changeDictionary.Clear();
                            }
                            Debug.Write("xss filter exception: " + ex.ToString() + "|||" + ty);
                        }
                    }
                }
            }

            foreach (var changePara in changeDictionary)
            {
                try
                {
                    filterContext.ActionParameters[changePara.Key] = changePara.Value;
                }
                catch (Exception ex)
                {
                    Debug.Write("xss filter exception:" + ex.ToString());
                    //throw;
                }
            }
        }
        private IEnumerable<PropertyInfo> GetProperties(Type type)
        {
            PropertyInfo[] properties = type.GetProperties();
            foreach (PropertyInfo property in properties)
            {
                if (property.PropertyType.GetInterfaces().Any(x => x == typeof(IList)))
                {
                    foreach (var prop in GetProperties(property.PropertyType.GetGenericArguments()[0]))
                        yield return prop;
                }
                else
                {
                    if (property.PropertyType.Assembly == type.Assembly)
                    {
                        if (property.PropertyType.IsClass)
                        {
                            yield return property;
                        }
                        GetProperties(property.PropertyType);
                    }
                    else
                    {
                        yield return property;
                    }
                }
            }
        }
        private void XssControl(IDictionary<string, object> parameters)
        {
            Dictionary<string, object> changeDictionary = new Dictionary<string, object>();
            foreach (var para in parameters)
            {
                if (para.Value?.GetType() == typeof(string))
                {

                    var value = para.Value as string;
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        value = Sanitizer.GetSafeHtmlFragment(value);
                        changeDictionary.Add(para.Key, value);
                    }
                }
                else if (para.Value != null && para.Value?.GetType().IsClass == true)
                {
                    var clss = para.Value?.GetType();
                    var obj = clss.Assembly.CreateInstance(clss.FullName);
                    foreach (PropertyInfo prop in clss.GetProperties())
                    {
                        string propName = prop.Name;
                        var val = para.Value.GetType().GetProperty(propName).GetValue(para.Value, null);
                        if (val?.GetType() == typeof(string))
                        {

                            string valuse = Sanitizer.GetSafeHtmlFragment(val.ToString());
                            SetValue(obj, prop.Name, valuse);
                        }
                    }
                    changeDictionary.Add(para.Key, obj);
                }
                else if (para.Value != null)
                {
                    var ty = para.Value.ToString();
                    if (ty != null && ty.Contains("{"))
                    {
                        var clss = para.Value?.GetType();
                        var obj = clss.Assembly.CreateInstance(clss.FullName);
                        try
                        {

                            var vls = clss.GetProperties();
                            foreach (PropertyInfo item in vls)
                            {
                                //original value
                                var yvue = item.GetValue(para.Value, null).ToString();
                                //tehlikeli karakter kontrolü
                                var isxss = !string.IsNullOrEmpty(Regex.Match(yvue, @"<|>|(|)&lt|%3c|script")?.Value);
                                if (isxss)
                                {
                                    //gelen içeriği güvenli hale getirme
                                    var vlue = Sanitizer.GetSafeHtmlFragment(item.GetValue(para.Value, null).ToString()).Replace("script", "");
                                    //sınıfın içerğini atama
                                    SetValue(obj, item.Name, vlue);
                                }
                                else
                                {
                                    SetValue(obj, item.Name, yvue);
                                }
                            }
                            changeDictionary.Add(para.Key, obj);

                        }
                        catch (Exception ex)
                        {
                            // hata da yanlış kayıt gitmesini engelleme
                            if (changeDictionary?.Count > 0)
                            {
                                changeDictionary.Clear();
                            }
                            Debug.Write("xss filter exception: " + ex.ToString() + "|||" + ty);
                        }

                    }
                }
            }
            foreach (var changePara in changeDictionary)
            {
                try
                {
                    parameters[changePara.Key] = changePara.Value;
                }
                catch (Exception ex)
                {
                    Debug.Write("xss filter exception:" + ex.ToString());
                }
            }
        }
        public static Dictionary<string, object> ObjectToDictionary(object obj)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();

            foreach (PropertyInfo prop in obj.GetType().GetProperties())
            {
                string propName = prop.Name;
                var val = obj.GetType().GetProperty(propName).GetValue(obj, null);
                if (val != null)
                {
                    ret.Add(propName, val);
                }
                else
                {
                    ret.Add(propName, null);
                }
            }

            return ret;
        }
        public static bool IsType(Type type, string typeName)
        {
            if (type.ToString() == typeName)
                return true;
            if (type.ToString() == "System.Object")
                return false;

            return IsType(type.BaseType, typeName);
        }
        public static void SetValue(object entity, string fieldName, string fieldValue)
        {
            Type entityType = entity.GetType();

            PropertyInfo propertyInfo = entityType.GetProperty(fieldName);

            if (IsType(propertyInfo.PropertyType, "System.String"))
            {
                propertyInfo.SetValue(entity, fieldValue, null);

            }

            if (IsType(propertyInfo.PropertyType, "System.Boolean"))
            {
                propertyInfo.SetValue(entity, Boolean.Parse(fieldValue), null);

            }

            if (IsType(propertyInfo.PropertyType, "System.Int32"))
            {
                if (fieldValue != "")
                    propertyInfo.SetValue(entity, int.Parse(fieldValue), null);
                else
                    propertyInfo.SetValue(entity, 0, null);

            }

            if (IsType(propertyInfo.PropertyType, "System.Decimal"))
            {
                if (fieldValue != "")
                    propertyInfo.SetValue(entity, Decimal.Parse(fieldValue), null);
                else
                    propertyInfo.SetValue(entity, new Decimal(0), null);

            }

            if (IsType(propertyInfo.PropertyType, "System.Nullable`1[System.DateTime]"))
            {
                if (fieldValue != "")
                {
                    try
                    {
                        propertyInfo.SetValue(entity, (DateTime?)Convert.ToDateTime(fieldValue), null);
                    }
                    catch
                    {
                        propertyInfo.SetValue(entity, (DateTime?)DateTime.ParseExact(fieldValue, "d.MM.yyyy", null), null);
                    }
                }
                else
                    propertyInfo.SetValue(entity, null, null);

            }

        }
    }
}